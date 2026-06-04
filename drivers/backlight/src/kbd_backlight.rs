//! Keyboard backlight — vendor WMI / ACPI control.
//!
//! Keyboard backlights on modern laptops are exposed through
//! vendor-specific WMI surfaces or ACPI methods. This module
//! provides:
//!
//! - [`KbdBacklightDevice`] — LED class device registered as
//!   `"<vendor>::kbd_backlight"` under the LED registry.
//! - Per-vendor WMI GUID tables and level encoders.
//! - The dispatch function called by the WMI event handler when a
//!   vendor-specific hotkey fires a keyboard-backlight change.
//!
//! ## Supported vendors
//!
//! ### Dell
//! WMI GUID `D93B5662-12B3-4D5F-8986-DE3E8D31E789` (`dell-wmi.c`).
//! Method `WMAX` function 0x12 sets the keyboard backlight level
//! (0 = off, 1 = low, 2 = high). Called via `invoke_method`.
//!
//! ### HP
//! WMI GUID `5FB7F034-2C63-45E9-BE91-3D44E2C707E4` (`hp-wmi.c`).
//! BIOS command 0x1A4 sets keyboard backlight on/off.
//!
//! ### Lenovo / ThinkPad (tpacpi)
//! WMI GUID `DC2A616E-2A5E-4E4A-80F3-AB7F11DFD1CA` (`thinkpad_acpi`).
//! Or via direct ACPI `\_SB.HKEY.MLCG` / `MLCS` methods.
//!
//! ### ASUS
//! WMI GUID `97845ED0-4E6D-11DE-8A39-0800200C9A66` (`asus-wmi.c`).
//! DWORD Arg1 encodes the backlight level for method DEVO/DEVS.
//!
//! ## Keyboard backlight as a LED device
//!
//! The device is registered under the LED subsystem with the name
//! `"<vendor>::kbd_backlight"` and `max_brightness` matching the
//! vendor's step count (e.g. 2 for Dell off/low/high → 0..=2).
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/platform/x86/dell-wmi.c` — `dell_wmi_notify`.
//! - `drivers/platform/x86/hp-wmi.c` — `hp_wmi_keyboard_backlight`.
//! - `drivers/platform/x86/thinkpad_acpi.c` — `TPACPI_DBG_BRIGHTNESS`.
//! - `drivers/platform/x86/asus-wmi.c` — `asus_wmi_set_devstate`.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::fmt::Write as FmtWrite;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_aml::wmi::{invoke_method, WmiGuid};
use narf_lib::sync::IrqSafeSpinLock;

use crate::leds::{register_led, unregister_led, LedDevice, Trigger};

// ── WMI GUIDs ─────────────────────────────────────────────────────

/// Dell WMI GUID for keyboard backlight (`WMAX` surface).
/// Source: `drivers/platform/x86/dell-wmi.c`, `DELL_WMI_GUID_BIOS_ARGS`.
pub const DELL_KBD_BL_GUID: [u8; 16] = [
    0x62, 0x56, 0x3b, 0xd9, // D93B5662 LE
    0xb3, 0x12, // 12B3 LE
    0x5f, 0x4d, // 4D5F LE
    0x86, 0x89, // 8986 BE
    0xde, 0x3e, 0x8d, 0x31, 0xe7, 0x89, // DE3E8D31E789 BE
];

/// HP WMI GUID for keyboard backlight.
/// Source: `drivers/platform/x86/hp-wmi.c`, `HP_WMI_BIOS_GUID`.
pub const HP_KBD_BL_GUID: [u8; 16] = [
    0x34, 0xf0, 0xb7, 0x5f, // 5FB7F034 LE
    0x63, 0x2c, // 2C63 LE
    0xe9, 0x45, // 45E9 LE
    0xbe, 0x91, // BE91 BE
    0x3d, 0x44, 0xe2, 0xc7, 0x07, 0xe4, // 3D44E2C707E4 BE
];

/// ASUS WMI GUID for keyboard backlight.
/// Source: `drivers/platform/x86/asus-wmi.c`, `ASUS_WMI_MGMT_GUID`.
pub const ASUS_KBD_BL_GUID: [u8; 16] = [
    0xd0, 0x5e, 0x84, 0x97, // 97845ED0 LE
    0x6d, 0x4e, // 4E6D LE
    0xde, 0x11, // 11DE LE
    0x8a, 0x39, // 8A39 BE
    0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66, // 0800200C9A66 BE
];

// ── Vendor enum ────────────────────────────────────────────────────

/// Known keyboard-backlight vendor types.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KbdBlVendor {
    Dell,
    Hp,
    Lenovo,
    Asus,
}

impl KbdBlVendor {
    /// LED device name prefix for this vendor.
    pub fn led_name(self) -> &'static str {
        match self {
            KbdBlVendor::Dell => "dell::kbd_backlight",
            KbdBlVendor::Hp => "hp::kbd_backlight",
            KbdBlVendor::Lenovo => "tpacpi::kbd_backlight",
            KbdBlVendor::Asus => "asus::kbd_backlight",
        }
    }

    /// Maximum brightness level for this vendor.
    pub fn max_level(self) -> u32 {
        match self {
            // Dell: 0 = off, 1 = low, 2 = high.
            KbdBlVendor::Dell => 2,
            // HP: 0 = off, 1 = on.
            KbdBlVendor::Hp => 1,
            // Lenovo ThinkPad: 0 = off, 1 = on, 2 = auto.
            KbdBlVendor::Lenovo => 2,
            // ASUS: typically 0–3.
            KbdBlVendor::Asus => 3,
        }
    }
}

// ── KbdBacklightDevice ─────────────────────────────────────────────

/// Keyboard backlight LED device. Registered with the LED subsystem
/// as `"<vendor>::kbd_backlight"`.
#[derive(Debug)]
pub struct KbdBacklightDevice {
    name: String,
    vendor: KbdBlVendor,
    /// Cached level (0..=max_level).
    cached: AtomicU32,
    max: u32,
    /// WMI GUID used to invoke the set method, if WMI-backed.
    wmi_guid: Option<WmiGuid>,
    /// ACPI path of the HKEY device, if ACPI-backed (Lenovo).
    acpi_hkey_path: Option<String>,
}

impl KbdBacklightDevice {
    /// Create a new keyboard backlight LED device.
    pub fn new(vendor: KbdBlVendor, wmi_guid: Option<WmiGuid>) -> Arc<Self> {
        let max = vendor.max_level();
        Arc::new(Self {
            name: vendor.led_name().to_string(),
            vendor,
            cached: AtomicU32::new(0),
            max,
            wmi_guid,
            acpi_hkey_path: None,
        })
    }

    /// Create a new ACPI-backed keyboard backlight LED device (Lenovo ThinkPad).
    pub fn new_acpi(vendor: KbdBlVendor, hkey_path: String) -> Arc<Self> {
        let max = vendor.max_level();
        Arc::new(Self {
            name: vendor.led_name().to_string(),
            vendor,
            cached: AtomicU32::new(0),
            max,
            wmi_guid: None,
            acpi_hkey_path: Some(hkey_path),
        })
    }

    /// Set the brightness level via the vendor's WMI method.
    ///
    /// Dell: `WMAX` function 0x12; Arg1 = level (0..=2).
    /// HP: `HPWMI` BIOS command 0x1A4; Arg = level.
    /// ASUS: `DEVS` with device-id 0x00050021; Arg = level.
    /// Lenovo: direct ACPI method path (WMI not used here).
    ///
    /// Reference:
    /// - Dell: `drivers/platform/x86/dell-wmi.c::dell_wmi_kbd_backlight_set`.
    /// - HP: `drivers/platform/x86/hp-wmi.c::hp_wmi_keyboard_backlight`.
    /// - ASUS: `drivers/platform/x86/asus-wmi.c::asus_wmi_set_devstate`.
    fn write_level_wmi(&self, level: u32) {
        let Some(guid) = &self.wmi_guid else {
            // No WMI — direct ACPI or GPIO; not implemented yet.
            return;
        };

        match self.vendor {
            KbdBlVendor::Dell => {
                // Dell WMAX keyboard-backlight: method_id = 0x12, Arg1 = level.
                // Reference: dell_wmi.c `dell_wmi_kbd_backlight_set`.
                let _ = invoke_method(guid, 0x12, &[narf_aml::Value::Integer(level as u64)]);
            }
            KbdBlVendor::Hp => {
                // HP: BIOS command 0x1A4 with level as argument.
                // Reference: hp_wmi.c `hp_wmi_keyboard_backlight`.
                let _ = invoke_method(guid, 0x1A4, &[narf_aml::Value::Integer(level as u64)]);
            }
            KbdBlVendor::Asus => {
                // ASUS: DEVS with device-id 0x00050021.
                // Reference: asus_wmi.c `asus_wmi_set_devstate`.
                let _ = invoke_method(guid, 0x00050021, &[narf_aml::Value::Integer(level as u64)]);
            }
            KbdBlVendor::Lenovo => {
                // ThinkPad uses direct ACPI; WMI path not used.
            }
        }
    }
}

impl LedDevice for KbdBacklightDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max
    }

    fn brightness(&self) -> u32 {
        if self.vendor == KbdBlVendor::Lenovo {
            if let Some(hkey_path) = &self.acpi_hkey_path {
                let method = alloc::format!("{}.MLCG", hkey_path);
                if let Ok(val) =
                    narf_aml::eval::evaluate_method(&method, &[narf_aml::Value::Integer(0)])
                {
                    let status = val.as_integer() as u32;
                    return status & 0x3;
                }
            }
        }
        self.cached.load(Ordering::Acquire)
    }

    fn set_brightness(&self, level: u32) {
        let clamped = level.min(self.max);
        if self.vendor == KbdBlVendor::Lenovo {
            if let Some(hkey_path) = &self.acpi_hkey_path {
                let method = alloc::format!("{}.MLCS", hkey_path);
                let _ = narf_aml::eval::evaluate_method(
                    &method,
                    &[narf_aml::Value::Integer(clamped as u64)],
                );
            }
        } else {
            self.write_level_wmi(clamped);
        }
        self.cached.store(clamped, Ordering::Release);
    }

    fn set_trigger(&self, _trigger: Trigger) {
        // Keyboard backlights don't support software triggers.
    }

    fn current_trigger(&self) -> Trigger {
        Trigger::None
    }
}

// ── Global installed kbd backlight ────────────────────────────────

static KBD_BL: IrqSafeSpinLock<Option<Arc<KbdBacklightDevice>>> = IrqSafeSpinLock::new(None);

/// Return the currently-installed keyboard backlight device, if any.
pub fn kbd_backlight_device() -> Option<Arc<KbdBacklightDevice>> {
    KBD_BL.lock().clone()
}

/// Install a keyboard backlight LED device. Replaces any previous entry.
pub fn install(dev: Arc<KbdBacklightDevice>) {
    let prev = KBD_BL.lock().replace(dev.clone());
    if let Some(p) = prev {
        unregister_led(p.name());
    }
    register_led(dev as Arc<dyn LedDevice>);
}

// ── Dell WMI level encode helpers ─────────────────────────────────

/// Encode a Dell keyboard-backlight level for the `WMAX` WMI method.
///
/// Dell supports three levels: 0 = off, 1 = low, 2 = high.
/// The encoding is a 4-byte buffer: `[level, 0, 0, 0]`.
///
/// Reference: `drivers/platform/x86/dell-wmi.c::dell_wmi_kbd_backlight_set`.
pub fn dell_encode_kbd_level(level: u32) -> [u8; 4] {
    [(level.min(2) as u8), 0, 0, 0]
}

// ── initcall ──────────────────────────────────────────────────────

/// Probe for vendor keyboard backlight WMI GUIDs and install the
/// matching [`KbdBacklightDevice`].
///
/// Called from the Stage::Device initcall in
/// [`crate::register_initcalls`]. Tries Dell → HP → ASUS in order;
/// first match wins. Lenovo ThinkPad uses a direct ACPI path
/// (`\_SB.HKEY.MLCG/MLCS`) which is separate from WMI enumeration
/// and is not yet implemented.
pub fn init() {
    let guids = narf_aml::wmi::list_guids();

    for vendor_guid in [
        (&DELL_KBD_BL_GUID, KbdBlVendor::Dell),
        (&HP_KBD_BL_GUID, KbdBlVendor::Hp),
        (&ASUS_KBD_BL_GUID, KbdBlVendor::Asus),
    ] {
        let (raw_guid, vendor) = vendor_guid;
        if let Some(wmi_guid) = guids.iter().find(|g| &g.guid == raw_guid).cloned() {
            let dev = KbdBacklightDevice::new(vendor, Some(wmi_guid));
            install(dev);
            let _ = writeln!(
                narf_console::Writer,
                "  kbd-backlight: registered {} ({:?})",
                vendor.led_name(),
                vendor
            );
            return;
        }
    }

    // Try Lenovo ThinkPad ACPI HKEY detection next.
    for hid in &["LEN0268", "IBM0068", "LEN0018"] {
        for dev in narf_aml::find_all_devices_by_hid(hid) {
            // Check if MLCG is supported on this device.
            // MLCG(0) must return a value where bit 9 (0x200) is set.
            let method = alloc::format!("{}.MLCG", dev.path);
            if let Ok(val) =
                narf_aml::eval::evaluate_method(&method, &[narf_aml::Value::Integer(0)])
            {
                let status = val.as_integer();
                if status & 0x200 != 0 {
                    let kbd_dev =
                        KbdBacklightDevice::new_acpi(KbdBlVendor::Lenovo, dev.path.clone());
                    install(kbd_dev);
                    let _ = writeln!(
                        narf_console::Writer,
                        "  kbd-backlight: registered tpacpi::kbd_backlight (Lenovo)"
                    );
                    return;
                }
            }
        }
    }

    let _ = writeln!(
        narf_console::Writer,
        "  kbd-backlight: no supported WMI GUID or ACPI interface found"
    );
}
