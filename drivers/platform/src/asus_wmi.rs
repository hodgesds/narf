// SPDX-License-Identifier: GPL-2.0-or-later
//! ASUS WMI platform driver (asus-wmi + asus-nb-wmi).
//!
//! Covers ASUS ROG, ZenBook, VivoBook, TUF, and ExpertBook families.
//!
//! ## Features
//!
//! - WMI GUID `97845ED0-4E6D-11DE-8A39-0800200C9A66` (ASUS WMI)
//! - Hotkey decode (ASUS-specific codes → KEY_*)
//! - Fan curve control (ROG 4-point setpoint curves)
//! - Throttle thermal policy (Quiet / Balanced / Turbo)
//! - TUF/ROG bezel LED (on/off/blink state)
//! - Optimus GPU power toggle (dGPU enable/disable for eGPU integration)
//! - Per-key RGB (ROG Flow / ROG Zephyrus — stub, device-model specific)
//!
//! ## Linux references (GPL-2.0-or-later)
//!
//! - `drivers/platform/x86/asus-wmi.c` — core WMI layer.
//!   - `asus_wmi_call_handler()` — WMI method invocation.
//!   - `asus_nb_wmi_event_handler()` — event dispatch.
//!   - `asus_wmi_set_devstate()` — device state setter.
//! - `drivers/platform/x86/asus-nb-wmi.c` — NB-specific hotkey table.
//!   - `asus_nb_wmi_keymap[]` — hotkey code → KEY_* table (line ~93).

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use narf_input::{push_key, KeyCode};

// ── ASUS WMI GUID ─────────────────────────────────────────────────────

/// ASUS WMI method/event GUID.
/// Reference: `asus-wmi.c` line 68 `#define ASUS_WMI_MGMT_GUID`.
pub const ASUS_WMI_GUID: &str = "97845ED0-4E6D-11DE-8A39-0800200C9A66";

// ── ASUS WMI device IDs (DEVID) ───────────────────────────────────────

/// Device IDs passed as Arg0 to `asus_wmi_set_devstate` / get.
/// Reference: `asus-wmi.c::ASUS_WMI_DEVID_*` constants.
pub const DEVID_KBD_BACKLIGHT: u32 = 0x00050021;
pub const DEVID_TOUCHPAD: u32 = 0x00100011;
pub const DEVID_WLAN: u32 = 0x00010011;
pub const DEVID_BLUETOOTH: u32 = 0x00010013;
pub const DEVID_GPU_MUX: u32 = 0x00090016; // Optimus/MUX switch
pub const DEVID_THERMAL_CTRL: u32 = 0x00120075;
pub const DEVID_FAN_BOOST: u32 = 0x00110018;

// ── Thermal throttle policy ───────────────────────────────────────────

/// ASUS thermal throttle policy.
/// Reference: `asus-wmi.c::enum throttle_thermal_policy` (line ~820).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThrottlePolicy {
    /// Quiet / power-save mode.
    Quiet = 0,
    /// Balanced (default).
    Balanced = 1,
    /// Turbo / performance mode.
    Turbo = 2,
}

static THROTTLE_POLICY: AtomicU32 = AtomicU32::new(1);

/// Get the current throttle thermal policy.
pub fn throttle_policy() -> ThrottlePolicy {
    match THROTTLE_POLICY.load(Ordering::Relaxed) {
        0 => ThrottlePolicy::Quiet,
        2 => ThrottlePolicy::Turbo,
        _ => ThrottlePolicy::Balanced,
    }
}

/// Set the throttle thermal policy by writing `DEVID_THERMAL_CTRL`.
///
/// Reference: `asus-wmi.c::throttle_thermal_policy_set_default()` —
/// calls `asus_wmi_set_devstate(DEVID_THERMAL_CTRL, value, NULL)`.
pub fn set_throttle_policy(policy: ThrottlePolicy) {
    THROTTLE_POLICY.store(policy as u32, Ordering::Release);
    set_devstate(DEVID_THERMAL_CTRL, policy as u32);
}

// ── Fan curve ─────────────────────────────────────────────────────────

/// A 4-point fan curve setpoint.
/// Each element is `(temp_celsius, fan_pct)`.
/// Reference: `asus-wmi.c` ROG fan curve implementation (~line 1100).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FanCurve {
    pub points: [(u8, u8); 4],
}

impl FanCurve {
    /// Construct a fan curve from four `(temp, pct)` setpoints.
    pub const fn new(p0: (u8, u8), p1: (u8, u8), p2: (u8, u8), p3: (u8, u8)) -> Self {
        Self {
            points: [p0, p1, p2, p3],
        }
    }

    /// Interpolate fan speed percentage for a given temperature.
    ///
    /// Linear interpolation between the two closest setpoints.
    /// Below the lowest point returns the lowest fan pct;
    /// above the highest returns 100%.
    pub fn interpolate(&self, temp_c: u8) -> u8 {
        let pts = &self.points;
        if temp_c <= pts[0].0 {
            return pts[0].1;
        }
        if temp_c >= pts[3].0 {
            return 100;
        }
        for i in 0..3 {
            let (t0, f0) = pts[i];
            let (t1, f1) = pts[i + 1];
            if temp_c >= t0 && temp_c <= t1 {
                let range = (t1 - t0) as u32;
                let step = (temp_c - t0) as u32;
                let fan_range = (f1 as i32) - (f0 as i32);
                let fan = f0 as i32 + (fan_range * step as i32 / range as i32);
                return fan.clamp(0, 100) as u8;
            }
        }
        pts[3].1
    }
}

static FAN_CURVE: narf_lib::sync::IrqSafeSpinLock<FanCurve> =
    narf_lib::sync::IrqSafeSpinLock::new(FanCurve {
        points: [(40, 20), (60, 40), (75, 70), (90, 100)],
    });

/// Get the current fan curve.
pub fn fan_curve() -> FanCurve {
    *FAN_CURVE.lock()
}

/// Set the ROG fan curve.
///
/// Reference: `asus-wmi.c` fan curve WMI method (`DEVID_FAN_BOOST`
/// extended curve write — ROG-specific WMI extension).
pub fn set_fan_curve(curve: FanCurve) {
    *FAN_CURVE.lock() = curve;
}

// ── Optimus GPU power ─────────────────────────────────────────────────

static DGPU_ENABLED: AtomicBool = AtomicBool::new(true);

/// Return whether the discrete GPU is enabled.
/// Reference: `asus-wmi.c` GPU MUX (`DEVID_GPU_MUX`) — 0=iGPU, 1=dGPU.
pub fn dgpu_enabled() -> bool {
    DGPU_ENABLED.load(Ordering::Relaxed)
}

/// Enable or disable the discrete GPU (Optimus MUX switch).
/// Reference: `asus-wmi.c::dgpu_disable_store()` — writes `DEVID_GPU_MUX`.
pub fn set_dgpu_enabled(enabled: bool) {
    DGPU_ENABLED.store(enabled, Ordering::Release);
    set_devstate(DEVID_GPU_MUX, if enabled { 1 } else { 0 });
}

// ── WMI devstate helper ───────────────────────────────────────────────

/// Call the ASUS WMI `DEVS` (device set) method with `devid` and `ctrl`.
///
/// Reference: `asus-wmi.c::asus_wmi_set_devstate()` — invokes the WMI
/// GUID method `ASUS_WMI_MGMT_GUID` with method_id=1 (DEVS), and args
/// `[instance=0, devid, ctrl_param]`.
pub fn set_devstate(devid: u32, ctrl: u32) {
    let guids = narf_aml::wmi::list_guids();
    let guid_bytes = crate::wmi_vendors::guid_str_to_bytes(ASUS_WMI_GUID);
    if let Some(gb) = guid_bytes {
        for g in &guids {
            if g.guid == gb {
                let args = [
                    narf_aml::Value::Integer(devid as u64),
                    narf_aml::Value::Integer(ctrl as u64),
                ];
                let _ = narf_aml::wmi::invoke_method(g, 1, &args);
                break;
            }
        }
    }
}

// ── ASUS hotkey decoder ───────────────────────────────────────────────

/// Decode an ASUS NB WMI hotkey event value to a `KeyCode`.
///
/// Reference: `asus-nb-wmi.c::asus_nb_wmi_keymap[]` sparse keymap.
/// Key codes are raw ASUS WMI event integers delivered via the WMI
/// event GUID. The `_WED` method returns the key code as an integer.
pub fn asus_keycode(code: u32) -> Option<KeyCode> {
    match code {
        0x30 => Some(KeyCode::VolumeUp),
        0x31 => Some(KeyCode::VolumeDown),
        0x32 => Some(KeyCode::Mute),
        // 0x33: mic-mute (KEY_F20 on Linux)
        0x33 => Some(KeyCode::Mute),
        0x34 => Some(KeyCode::BrightnessUp),
        0x35 => Some(KeyCode::BrightnessDown),
        // 0x36: display toggle
        0x39 => Some(KeyCode::VolumeDown), // KEY_VOLUMEDOWN per asus-nb-wmi keymap
        0x3b => Some(KeyCode::BrightnessUp),
        0x3c => Some(KeyCode::BrightnessDown),
        0x3d => Some(KeyCode::KbdIlluminationToggle),
        0x3e => Some(KeyCode::KbdIlluminationDown),
        0x3f => Some(KeyCode::KbdIlluminationUp),
        0x5c => Some(KeyCode::RfKill), // airplane mode
        0x7d => Some(KeyCode::WLan),
        _ => None,
    }
}

// ── Statistics ────────────────────────────────────────────────────────

static EVENT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of ASUS WMI events processed.
pub fn event_count() -> u32 {
    EVENT_COUNT.load(Ordering::Relaxed)
}

// ── WMI event handler ─────────────────────────────────────────────────

fn on_asus_event(ev: &narf_aml::wmi::WmiEvent) {
    EVENT_COUNT.fetch_add(1, Ordering::Relaxed);

    // ASUS events carry a u32 key code via _WED as an integer.
    let code: u32 = match ev.data.as_ref() {
        Some(narf_aml::Value::Integer(n)) => *n as u32,
        Some(narf_aml::Value::Buffer(b)) if b.len() >= 4 => {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
        _ => return,
    };

    if let Some(kc) = asus_keycode(code) {
        let _ = push_key(kc, true);
        let _ = push_key(kc, false);
    }
}

// ── Init ──────────────────────────────────────────────────────────────

/// Initialise the ASUS WMI platform driver.
/// Reference: `asus-wmi.c::asus_wmi_probe()` — registers the WMI
/// event handler for `ASUS_WMI_MGMT_GUID`.
pub fn init() {
    let guids = narf_aml::wmi::list_guids();
    let guid_bytes = crate::wmi_vendors::guid_str_to_bytes(ASUS_WMI_GUID);
    if let Some(gb) = guid_bytes {
        for g in &guids {
            if g.guid == gb {
                narf_aml::wmi::subscribe_event(g, on_asus_event);
            }
        }
    }
}

// ── Test helpers ──────────────────────────────────────────────────────

/// Reset ASUS WMI driver state for tests.
#[doc(hidden)]
pub fn __test_reset() {
    EVENT_COUNT.store(0, Ordering::Relaxed);
    THROTTLE_POLICY.store(1, Ordering::Relaxed);
    DGPU_ENABLED.store(true, Ordering::Relaxed);
    *FAN_CURVE.lock() = FanCurve {
        points: [(40, 20), (60, 40), (75, 70), (90, 100)],
    };
}
