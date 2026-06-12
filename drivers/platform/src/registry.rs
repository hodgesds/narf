// SPDX-License-Identifier: GPL-2.0-or-later
//! Platform driver registry — vendor probe + dispatch table.
//!
//! On init, `probe_and_register()` queries SMBIOS system manufacturer
//! string, then delegates to the matching vendor driver.
//!
//! ## Vendor probe order
//!
//! 1. SMBIOS Type-1 `manufacturer` — "LENOVO" → route by sub-model
//!    (ThinkPad via HKEY HID, IdeaPad/Yoga via VPC2004 ACPI HID).
//! 2. SMBIOS `manufacturer` — "Dell Inc." / "DELL" → dell_laptop.
//! 3. SMBIOS `manufacturer` — "HP" / "Hewlett-Packard" → hp_wmi.
//! 4. SMBIOS `manufacturer` — "ASUSTeK" / "ASUS" → asus_wmi.
//! 5. SMBIOS `manufacturer` — "SAMSUNG ELECTRONICS" → samsung_laptop.
//!
//! Reference: Linux `drivers/platform/x86/` per-driver DMI tables
//! (thinkpad_acpi.c, ideapad-laptop.c, dell-laptop.c, hp-wmi.c, etc.)
//! all use `dmi_check_system()` with the same manufacturer strings.

extern crate alloc;

use core::sync::atomic::{AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Vendor identity ────────────────────────────────────────────────────

/// Top-level OEM identity, as determined by SMBIOS manufacturer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OemVendor {
    /// Lenovo ThinkPad family (HKEY ACPI device present).
    ThinkPad,
    /// Lenovo IdeaPad / Yoga (VPC2004 ACPI device present).
    IdeaPad,
    /// Dell laptop (XPS, Latitude, Inspiron, Precision).
    Dell,
    /// HP laptop (EliteBook, Spectre, Pavilion, Omen).
    Hp,
    /// ASUS laptop (ROG, ZenBook, VivoBook, TUF).
    Asus,
    /// Samsung laptop (Notebook 9, Galaxy Book).
    Samsung,
    /// Acer laptop (Aspire, Predator, Swift).
    Acer,
    /// Unknown / not a laptop vendor we handle.
    Unknown,
}

impl OemVendor {
    /// Determine OEM from a SMBIOS Type-1 manufacturer string.
    ///
    /// Reference: Linux per-driver DMI tables — each driver calls
    /// `dmi_check_system()` against its own `dmi_system_id` table with
    /// the same manufacturer strings. We unify them here.
    pub fn from_manufacturer(mfr: &str) -> Self {
        let v = mfr.trim();
        if v.eq_ignore_ascii_case("LENOVO") {
            return OemVendor::ThinkPad; // caller refines to IdeaPad if needed
        }
        if v.starts_with("Dell") || v.eq_ignore_ascii_case("DELL") {
            return OemVendor::Dell;
        }
        if v.eq_ignore_ascii_case("HP")
            || v.eq_ignore_ascii_case("Hewlett-Packard")
            || v.starts_with("HP ")
        {
            return OemVendor::Hp;
        }
        if v.contains("ASUSTeK") || v.eq_ignore_ascii_case("ASUS") {
            return OemVendor::Asus;
        }
        if v.contains("SAMSUNG") {
            return OemVendor::Samsung;
        }
        if v.eq_ignore_ascii_case("Acer") {
            return OemVendor::Acer;
        }
        OemVendor::Unknown
    }

    /// Refine a Lenovo tentative classification by checking which ACPI
    /// device HID is present: HKEY → ThinkPad; VPC2004 → IdeaPad.
    ///
    /// Reference:
    /// - `thinkpad_acpi.c::tp_acpi_check_dmi` — probes for HKEY HID.
    /// - `ideapad-laptop.c::ideapad_acpi_match` — matches VPC2004.
    pub fn refine_lenovo(self) -> Self {
        if self != OemVendor::ThinkPad {
            return self;
        }
        // ThinkPad HKEY device HIDs.
        for hid in &["LEN0268", "IBM0068", "LEN0018"] {
            if !narf_aml::find_all_devices_by_hid(hid).is_empty() {
                return OemVendor::ThinkPad;
            }
        }
        // IdeaPad VPC2004 device.
        if !narf_aml::find_all_devices_by_hid("VPC2004").is_empty() {
            return OemVendor::IdeaPad;
        }
        // Default to ThinkPad if neither is found (conservative).
        OemVendor::ThinkPad
    }
}

// ── Detected vendor ───────────────────────────────────────────────────

static DETECTED_OEM: IrqSafeSpinLock<Option<OemVendor>> = IrqSafeSpinLock::new(None);
static DRIVERS_INIT: AtomicU8 = AtomicU8::new(0);

/// Return the detected OEM set by `probe_and_register()`.
pub fn detected_oem() -> Option<OemVendor> {
    *DETECTED_OEM.lock()
}

/// Number of vendor platform drivers successfully initialised.
pub fn drivers_init_count() -> u8 {
    DRIVERS_INIT.load(Ordering::Relaxed)
}

// ── Registry errors ───────────────────────────────────────────────────

/// Errors from the platform driver registry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// SMBIOS data was unavailable.
    NoSmbios,
    /// No matching vendor driver for this platform.
    UnknownVendor,
}

// ── Probe ─────────────────────────────────────────────────────────────

/// Read the SMBIOS Type-1 manufacturer string and identify the OEM.
/// Returns `None` if SMBIOS data is not yet available.
pub fn read_manufacturer() -> Option<alloc::string::String> {
    #[cfg(not(test))]
    {
        let mut sys = [narf_firmware_smbios::SmbiosSystem::ZERO; 1];
        if narf_firmware_smbios::copy_system(&mut sys) == 0 {
            return None;
        }
        // Manufacturer is a NUL-terminated C string in the 64-byte field.
        let mfr = &sys[0].manufacturer;
        let end = mfr.iter().position(|&b| b == 0).unwrap_or(64);
        Some(alloc::string::String::from_utf8_lossy(&mfr[..end]).into_owned())
    }
    #[cfg(test)]
    {
        TEST_MFR.lock().clone()
    }
}

/// Probe the platform vendor and initialise the appropriate driver.
/// Idempotent — repeated calls update the detection result.
pub fn probe_and_register() -> Result<OemVendor, RegistryError> {
    let mfr = read_manufacturer().ok_or(RegistryError::NoSmbios)?;
    let mut oem = OemVendor::from_manufacturer(&mfr);

    if oem == OemVendor::ThinkPad {
        oem = oem.refine_lenovo();
    }

    *DETECTED_OEM.lock() = Some(oem);

    match oem {
        OemVendor::ThinkPad => {
            crate::thinkpad_acpi::init();
            DRIVERS_INIT.fetch_add(1, Ordering::Relaxed);
        }
        OemVendor::IdeaPad => {
            crate::ideapad_laptop::init();
            DRIVERS_INIT.fetch_add(1, Ordering::Relaxed);
        }
        OemVendor::Dell => {
            crate::dell_laptop::init();
            DRIVERS_INIT.fetch_add(1, Ordering::Relaxed);
        }
        OemVendor::Hp => {
            crate::hp_wmi::init();
            DRIVERS_INIT.fetch_add(1, Ordering::Relaxed);
        }
        OemVendor::Asus => {
            crate::asus_wmi::init();
            DRIVERS_INIT.fetch_add(1, Ordering::Relaxed);
        }
        OemVendor::Samsung => {
            crate::samsung_laptop::init();
            DRIVERS_INIT.fetch_add(1, Ordering::Relaxed);
        }
        OemVendor::Acer => {
            crate::acer_wmi::init();
            DRIVERS_INIT.fetch_add(1, Ordering::Relaxed);
        }
        OemVendor::Unknown => return Err(RegistryError::UnknownVendor),
    }

    Ok(oem)
}

// ── Test helpers ──────────────────────────────────────────────────────

#[cfg(test)]
static TEST_MFR: IrqSafeSpinLock<Option<alloc::string::String>> = IrqSafeSpinLock::new(None);

/// Inject a synthetic manufacturer string for unit tests.
#[doc(hidden)]
#[cfg(test)]
pub fn __test_set_manufacturer(s: &str) {
    *TEST_MFR.lock() = Some(alloc::string::ToString::to_string(s));
}

/// Reset registry state for unit tests.
#[doc(hidden)]
pub fn __test_reset() {
    *DETECTED_OEM.lock() = None;
    DRIVERS_INIT.store(0, Ordering::Relaxed);
    #[cfg(test)]
    {
        *TEST_MFR.lock() = None;
    }
}
