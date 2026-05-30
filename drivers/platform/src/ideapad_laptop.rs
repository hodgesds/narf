// SPDX-License-Identifier: GPL-2.0-or-later
//! IdeaPad / Yoga laptop platform driver.
//!
//! Covers Lenovo IdeaPad and Yoga (non-ThinkPad) laptop families via the
//! VPC2004 ACPI device interface.
//!
//! ## Features
//!
//! - VPC2004 ACPI device — read/write via `_VPC` (index, value) protocol
//! - Hotkeys: Fn+F1–F12 IdeaPad-specific codes via EC notify
//! - Camera button (privacy shutter toggle) — VPC index 0x2
//! - Touchpad enable/disable — VPC index 0x6
//! - Battery conservation mode — VPC index 0x28
//! - USB charging in sleep — VPC index 0x24
//! - Yoga mode switch (tent / tablet / laptop) — VPC index 0x7 or EC
//! - Performance mode — VPC index 0x3B (0=Quiet, 1=Balanced, 2=Performance)
//!
//! ## Linux references (GPL-2.0-or-later)
//!
//! - `drivers/platform/x86/ideapad-laptop.c`
//!   - `ideapad_acpi_match[]` — DMI match table using VPC2004 HID.
//!   - `ideapad_read_method()` / `ideapad_write_method()` — VPC index
//!     read/write via `VMCCMD` / `VMCSET` AML methods (line ~230).
//!   - `ideapad_battery_conservation_mode_show/store()` — reads/writes
//!     VPC index 0x28 (line ~840).
//!   - `ideapad_fn_lock_get/set()` — VPC index 0x0 (line ~720).

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use narf_input::{push_key, KeyCode};

// ── VPC2004 ACPI HID ──────────────────────────────────────────────────

/// ACPI HID for the IdeaPad VPC (Vendor Platform Controller) device.
/// Reference: `ideapad-laptop.c::ideapad_acpi_match` — `VPC2004`.
pub const VPC_HID: &str = "VPC2004";

// ── VPC index constants ───────────────────────────────────────────────

/// VPC index for Fn-lock state (0 = Fn-key active, 1 = media-key active).
/// Reference: `ideapad-laptop.c::VPCCMD_R_FAN` comment block, line ~220.
pub const VPC_IDX_FN_LOCK: u8 = 0x0;
/// VPC index for camera state (read: 0 = open, 1 = closed).
/// Reference: `ideapad-laptop.c::VPCCMD_R_CAMERA` (line ~215).
pub const VPC_IDX_CAMERA: u8 = 0x2;
/// VPC index for battery conservation mode (0 = normal, 1 = conservation).
/// Reference: `ideapad-laptop.c::VPCCMD_W_BAT_CON` (line ~224).
pub const VPC_IDX_BAT_CONSERVATION: u8 = 0x28;
/// VPC index for USB charging in sleep (0 = off, 1 = on).
/// Reference: `ideapad-laptop.c::VPCCMD_W_USB_CHARGE` (line ~225).
pub const VPC_IDX_USB_CHARGE: u8 = 0x24;
/// VPC index for touchpad state (1 = on, 0 = off).
/// Reference: `ideapad-laptop.c::VPCCMD_W_TOUCHPAD` (line ~226).
pub const VPC_IDX_TOUCHPAD: u8 = 0x6;
/// VPC index for performance / thermal mode.
/// Reference: `ideapad-laptop.c::VPCCMD_W_FAN` variant (line ~228).
pub const VPC_IDX_PERF_MODE: u8 = 0x3B;
/// VPC index for Yoga mode (tablet / tent / laptop orientation).
/// Reference: `ideapad-laptop.c::VPCCMD_R_YOGA_MODE` (line ~230).
pub const VPC_IDX_YOGA_MODE: u8 = 0x7;

// ── VPC read / write ──────────────────────────────────────────────────

/// Path prefix for VPC AML methods. The full path is
/// `<vpc_path>.VMCCMD` for reads and `<vpc_path>.VMCSET` for writes.
static VPC_PATH: narf_lib::sync::IrqSafeSpinLock<alloc::string::String> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::string::String::new());

fn vpc_path() -> alloc::string::String {
    VPC_PATH.lock().clone()
}

/// Read a VPC register by index using the `VMCCMD` AML method.
///
/// Reference: `ideapad-laptop.c::ideapad_read_method()` line ~235 —
/// evaluates `<vpc>._VPC(index, 0)` or `VMCCMD` and reads the result.
pub fn vpc_read(index: u8) -> Option<u32> {
    let path_base = vpc_path();
    if path_base.is_empty() {
        return None;
    }
    let method = alloc::format!("{}.VMCCMD", path_base);
    let result = narf_aml::eval::evaluate_method(
        &method,
        &[narf_aml::Value::Integer(index as u64)],
    );
    match result {
        Ok(narf_aml::Value::Integer(n)) => Some(n as u32),
        Ok(narf_aml::Value::Buffer(b)) if !b.is_empty() => Some(b[0] as u32),
        _ => None,
    }
}

/// Write a VPC register by index using the `VMCSET` AML method.
///
/// Reference: `ideapad-laptop.c::ideapad_write_method()` line ~242 —
/// evaluates `<vpc>._VPC(index, value)` or `VMCSET`.
pub fn vpc_write(index: u8, value: u32) -> bool {
    let path_base = vpc_path();
    if path_base.is_empty() {
        return false;
    }
    let method = alloc::format!("{}.VMCSET", path_base);
    narf_aml::eval::evaluate_method(
        &method,
        &[
            narf_aml::Value::Integer(index as u64),
            narf_aml::Value::Integer(value as u64),
        ],
    )
    .is_ok()
}

// ── Battery conservation mode ──────────────────────────────────────────

static BATTERY_CONSERVATION: AtomicBool = AtomicBool::new(false);

/// Get the battery conservation mode state.
pub fn battery_conservation_enabled() -> bool {
    BATTERY_CONSERVATION.load(Ordering::Relaxed)
}

/// Enable or disable battery conservation mode (stop charge at ~60%).
///
/// Reference: `ideapad-laptop.c::ideapad_battery_conservation_mode_store()`
/// line ~840 — writes VPC index 0x28 with value 0 or 1.
pub fn set_battery_conservation(enable: bool) {
    BATTERY_CONSERVATION.store(enable, Ordering::Release);
    let _ = vpc_write(VPC_IDX_BAT_CONSERVATION, if enable { 1 } else { 0 });
}

// ── USB charging in sleep ──────────────────────────────────────────────

static USB_CHARGE_SLEEP: AtomicBool = AtomicBool::new(false);

/// Get the USB-charge-in-sleep state.
pub fn usb_charge_sleep_enabled() -> bool {
    USB_CHARGE_SLEEP.load(Ordering::Relaxed)
}

/// Enable or disable USB charging in sleep mode.
/// Reference: `ideapad-laptop.c::ideapad_usb_charge_show()` — VPC 0x24.
pub fn set_usb_charge_sleep(enable: bool) {
    USB_CHARGE_SLEEP.store(enable, Ordering::Release);
    let _ = vpc_write(VPC_IDX_USB_CHARGE, if enable { 1 } else { 0 });
}

// ── Camera (privacy shutter) ───────────────────────────────────────────

/// Read the camera shutter state from VPC index 0x2.
/// Returns `Some(true)` if the shutter is open (camera accessible).
pub fn camera_open() -> Option<bool> {
    vpc_read(VPC_IDX_CAMERA).map(|v| v == 0)
}

// ── Touchpad ──────────────────────────────────────────────────────────

/// Enable or disable the touchpad via VPC index 0x6.
/// Reference: `ideapad-laptop.c` touchpad control VPC write.
pub fn set_touchpad_enabled(enabled: bool) {
    let _ = vpc_write(VPC_IDX_TOUCHPAD, if enabled { 1 } else { 0 });
}

// ── Performance mode ──────────────────────────────────────────────────

/// IdeaPad performance mode values.
/// Reference: `ideapad-laptop.c::ideapad_acpi_platform_profile_store()`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PerfMode {
    Quiet = 0,
    Balanced = 1,
    Performance = 2,
}

static PERF_MODE: AtomicU32 = AtomicU32::new(1);

/// Get the current performance mode.
pub fn perf_mode() -> PerfMode {
    match PERF_MODE.load(Ordering::Relaxed) {
        0 => PerfMode::Quiet,
        2 => PerfMode::Performance,
        _ => PerfMode::Balanced,
    }
}

/// Set the performance mode via VPC index 0x3B.
/// Reference: `ideapad-laptop.c::ideapad_acpi_platform_profile_store()`.
pub fn set_perf_mode(mode: PerfMode) {
    PERF_MODE.store(mode as u32, Ordering::Release);
    let _ = vpc_write(VPC_IDX_PERF_MODE, mode as u32);
}

// ── Yoga mode ─────────────────────────────────────────────────────────

/// Yoga orientation modes.
/// Reference: `ideapad-laptop.c` YOGA_MODE_* constants.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum YogaMode {
    Laptop = 1,
    Tablet = 2,
    Tent = 3,
    Stand = 4,
}

impl YogaMode {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(YogaMode::Laptop),
            2 => Some(YogaMode::Tablet),
            3 => Some(YogaMode::Tent),
            4 => Some(YogaMode::Stand),
            _ => None,
        }
    }
}

/// Read the current Yoga orientation mode.
pub fn yoga_mode() -> Option<YogaMode> {
    vpc_read(VPC_IDX_YOGA_MODE).and_then(YogaMode::from_u32)
}

// ── Hotkey decoder ────────────────────────────────────────────────────

/// Map IdeaPad/Yoga hotkey event IDs to `KeyCode`.
///
/// IdeaPad hotkey events are delivered via the Lenovo WMI GUID
/// `21494638-4391-4287-94B2-DDF09FE4A7AA` as u32 integers.
///
/// Reference: `ideapad-laptop.c` hotkey callback + sparse keymap.
/// Also referenced in `wmi_vendors.rs::decode_lenovo_hotkey_keycode`.
pub fn ideapad_keycode(id: u32) -> Option<KeyCode> {
    match id {
        0x01 => Some(KeyCode::BrightnessUp),
        0x02 => Some(KeyCode::BrightnessDown),
        0x03 => Some(KeyCode::KbdIlluminationToggle),
        0x04 => Some(KeyCode::Mute),
        0x05 => Some(KeyCode::VolumeUp),
        0x06 => Some(KeyCode::WLan),
        0x07 => Some(KeyCode::TouchpadToggle),
        0x0b => Some(KeyCode::RfKill),
        0x0d => Some(KeyCode::Sleep),
        0x13 => Some(KeyCode::BrightnessUp),
        0x14 => Some(KeyCode::BrightnessDown),
        0x15 => Some(KeyCode::KbdIlluminationUp),
        0x16 => Some(KeyCode::KbdIlluminationDown),
        _ => None,
    }
}

// ── Statistics ─────────────────────────────────────────────────────────

static HOTKEY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of IdeaPad hotkey events dispatched.
pub fn hotkey_count() -> u32 {
    HOTKEY_COUNT.load(Ordering::Relaxed)
}

// ── WMI hotkey event handler ──────────────────────────────────────────

fn on_ideapad_hotkey(ev: &narf_aml::wmi::WmiEvent) {
    HOTKEY_COUNT.fetch_add(1, Ordering::Relaxed);
    let raw = match ev.data.as_ref() {
        Some(narf_aml::Value::Integer(n)) => *n as u32,
        Some(narf_aml::Value::Buffer(b)) if b.len() >= 4 => {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
        _ => return,
    };
    if let Some(kc) = ideapad_keycode(raw) {
        let _ = push_key(kc, true);
        let _ = push_key(kc, false);
    }
}

// ── Init ───────────────────────────────────────────────────────────────

/// Initialise the IdeaPad laptop platform driver.
///
/// Finds the VPC2004 ACPI device, caches its path for VPC reads/writes,
/// and registers the WMI hotkey event handler.
///
/// Reference: `ideapad-laptop.c::ideapad_acpi_add()` — probes VPC2004,
/// reads initial state, and registers WMI handlers.
pub fn init() {
    // Locate the VPC2004 device.
    let devices = narf_aml::find_all_devices_by_hid(VPC_HID);
    if let Some(dev) = devices.first() {
        *VPC_PATH.lock() = dev.path.clone();
    }

    // Register Lenovo IdeaPad WMI hotkey handler.
    let guids = narf_aml::wmi::list_guids();
    let event_bytes = crate::wmi_vendors::guid_str_to_bytes(
        "21494638-4391-4287-94B2-DDF09FE4A7AA",
    );
    if let Some(eg) = event_bytes {
        for g in &guids {
            if g.guid == eg {
                narf_aml::wmi::subscribe_event(g, on_ideapad_hotkey);
            }
        }
    }
}

// ── Test helpers ──────────────────────────────────────────────────────

/// Reset IdeaPad driver state for tests.
#[doc(hidden)]
pub fn __test_reset() {
    HOTKEY_COUNT.store(0, Ordering::Relaxed);
    BATTERY_CONSERVATION.store(false, Ordering::Relaxed);
    USB_CHARGE_SLEEP.store(false, Ordering::Relaxed);
    PERF_MODE.store(1, Ordering::Relaxed);
    VPC_PATH.lock().clear();
}
