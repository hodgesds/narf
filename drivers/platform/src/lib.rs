//! Platform / chipset peripheral drivers.
//!
//! Clean-room implementations of standardised platform devices
//! whose specs are public (Intel ICH SMBus, TPM 2.0). Each driver
//! lives in its own module + registers via Stage::Subsys initcalls.
//!
//! - ACPI: <https://uefi.org/specs/ACPI/>
//! - TPM 2.0: <https://trustedcomputinggroup.org/resource/tpm-library-specification/>

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
pub mod ac_adapter;
#[cfg(target_arch = "x86_64")]
pub mod acer_wmi;
#[cfg(target_arch = "x86_64")]
pub mod alienware_wmi;
/// AMD AOAC (Always-On / Modern-Standby D-state control), x86-64 only.
#[cfg(target_arch = "x86_64")]
pub mod amd_aoac;
/// AMD ASF (Alert Standard Format) transport scaffold.
pub mod amd_asf;
pub mod backlight;
/// Battery / lid / buttons all consume the EC's platform-event
/// feed. On aarch64 the equivalent path goes through SoC-specific
/// PMIC drivers (not yet ported) — gate these on x86_64 too.
#[cfg(target_arch = "x86_64")]
pub mod battery;
#[cfg(target_arch = "x86_64")]
pub mod buttons;
/// EC uses x86 I/O ports (`narf_arch::x86_64::io_port`); not present
/// on aarch64 platforms, where the embedded controller is reached
/// through SoC-specific MMIO instead.
#[cfg(target_arch = "x86_64")]
pub mod ec;
/// EC hotkey → input-ring bridge. Lives next to the EC since
/// it depends on the EC's `_Qxx` registry to land events.
#[cfg(target_arch = "x86_64")]
pub mod ec_hotkeys;
pub mod fan;
pub mod intel_hid;
#[cfg(target_arch = "x86_64")]
pub mod lid;
pub mod smbus;
pub mod thermal;
pub mod tpm;
/// Vendor WMI hotkey dispatch — Dell, HP, and Lenovo laptop Fn-key
/// events delivered through ACPI WMI event GUIDs.
/// Must init after `narf-aml` WMI GUID enumeration (Stage::Subsys,
/// ordered after the ACPI namespace walk). Runs on any arch where
/// WMI-capable firmware is present; currently only x86_64 laptops
/// expose PNP0C14 WMI devices so gate it accordingly.
#[cfg(target_arch = "x86_64")]
pub mod wmi_vendors;

/// Shared WMI MOF/GUID helpers used by vendor platform drivers.
pub mod wmi_core;

/// Platform driver registry — vendor probe + per-driver init dispatch.
/// Identifies OEM via SMBIOS Type-1 manufacturer and routes to the
/// appropriate per-vendor driver at Stage::Subsys.
#[cfg(target_arch = "x86_64")]
pub mod registry;

/// Lenovo ThinkPad ACPI platform driver.
/// Hotkeys via HKEY, LED control, battery conservation, fan control.
#[cfg(target_arch = "x86_64")]
pub mod thinkpad_acpi;

/// Dell laptop platform driver.
/// SMBIOS SMI commands, WMI hotkeys, keyboard backlight, battery charge limit.
#[cfg(target_arch = "x86_64")]
pub mod dell_laptop;

/// HP WMI platform driver.
/// BIOS GUID queries, hotkeys, wireless toggle, Coolsense fan profile.
#[cfg(target_arch = "x86_64")]
pub mod hp_wmi;

/// ASUS WMI platform driver (asus-wmi + asus-nb-wmi).
/// Hotkeys, fan curves, throttle policy, Optimus GPU toggle.
#[cfg(target_arch = "x86_64")]
pub mod asus_wmi;

/// Lenovo IdeaPad / Yoga platform driver.
/// VPC2004 ACPI device, battery conservation, performance mode.
#[cfg(target_arch = "x86_64")]
pub mod ideapad_laptop;

/// Samsung laptop platform driver.
/// SABI SMI interface, hotkeys, performance mode, USB charge in sleep.
#[cfg(target_arch = "x86_64")]
pub mod samsung_laptop;
#[cfg(target_arch = "x86_64")]
pub mod surface_acpi;
#[cfg(target_arch = "x86_64")]
pub mod system76_acpi;

mod tests;

/// Stage::Subsys initcalls for this driver crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    #[cfg(target_arch = "x86_64")]
    alienware_wmi::register_initcalls();
    #[cfg(target_arch = "x86_64")]
    surface_acpi::register_initcalls();
    #[cfg(target_arch = "x86_64")]
    system76_acpi::register_initcalls();
    narf_init::register(Stage::Subsys, "smbus", || {
        smbus::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "tpm", || {
        tpm::try_init_default();
        InitResult::Ok
    });
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "acpi-ec", || {
        ec::init();
        InitResult::Ok
    });
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "acpi-battery", || {
        battery::init();
        InitResult::Ok
    });
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "acpi-ac-adapter", || {
        ac_adapter::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-thermal", || {
        thermal::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-fan", || {
        fan::init();
        InitResult::Ok
    });
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "acpi-lid", || {
        lid::init();
        InitResult::Ok
    });
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "acpi-buttons", || {
        buttons::init();
        InitResult::Ok
    });
    // EC hotkey bridge must register after acpi-ec (which installs
    // the SCI handler) but before any code that wants to inject
    // synthetic events for testing. Subsys order = registration
    // order within a stage, so this is correctly placed below
    // acpi-ec.
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "acpi-ec-hotkeys", || {
        ec_hotkeys::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "acpi-backlight", || {
        backlight::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "intel-hid", || {
        intel_hid::init();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "amd-asf", || {
        amd_asf::init();
        InitResult::Ok
    });
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "amd-aoac", || {
        // Best-effort: silently skip on non-AMD or unrecognised silicon.
        let _ = amd_aoac::init();
        InitResult::Ok
    });
    // WMI vendor dispatch must run after the AML namespace walk +
    // WMI GUID enumeration. Best-effort: on non-laptop or non-WMI
    // systems `init()` returns UnknownVendor and we skip silently.
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "wmi-vendors", || {
        let _ = wmi_vendors::init();
        InitResult::Ok
    });
    // Vendor platform driver registry: probe SMBIOS manufacturer,
    // then route to ThinkPad / IdeaPad / Dell / HP / ASUS / Samsung.
    // Must run after wmi-vendors (which ensures WMI GUIDs are listed).
    // Best-effort: UnknownVendor or NoSmbios just means not a laptop.
    #[cfg(target_arch = "x86_64")]
    narf_init::register(Stage::Subsys, "laptop-vendor-drivers", || {
        let _ = registry::probe_and_register();
        InitResult::Ok
    });
}
