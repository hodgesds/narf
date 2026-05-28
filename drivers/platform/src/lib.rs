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

pub mod smbus;
pub mod tpm;
/// EC uses x86 I/O ports (`narf_arch::x86_64::io_port`); not present
/// on aarch64 platforms, where the embedded controller is reached
/// through SoC-specific MMIO instead.
#[cfg(target_arch = "x86_64")]
pub mod ec;
/// Battery / lid / buttons all consume the EC's platform-event
/// feed. On aarch64 the equivalent path goes through SoC-specific
/// PMIC drivers (not yet ported) — gate these on x86_64 too.
#[cfg(target_arch = "x86_64")]
pub mod battery;
#[cfg(target_arch = "x86_64")]
pub mod ac_adapter;
pub mod thermal;
pub mod fan;
#[cfg(target_arch = "x86_64")]
pub mod lid;
#[cfg(target_arch = "x86_64")]
pub mod buttons;
/// EC hotkey → input-ring bridge. Lives next to the EC since
/// it depends on the EC's `_Qxx` registry to land events.
#[cfg(target_arch = "x86_64")]
pub mod ec_hotkeys;
pub mod backlight;
/// AMD AOAC (Always-On / Modern-Standby D-state control), x86-64 only.
#[cfg(target_arch = "x86_64")]
pub mod amd_aoac;
/// AMD ASF (Alert Standard Format) transport scaffold.
pub mod amd_asf;
/// Vendor WMI hotkey dispatch — Dell, HP, and Lenovo laptop Fn-key
/// events delivered through ACPI WMI event GUIDs.
/// Must init after `narf-aml` WMI GUID enumeration (Stage::Subsys,
/// ordered after the ACPI namespace walk). Runs on any arch where
/// WMI-capable firmware is present; currently only x86_64 laptops
/// expose PNP0C14 WMI devices so gate it accordingly.
#[cfg(target_arch = "x86_64")]
pub mod wmi_vendors;

mod tests;

/// Stage::Subsys initcalls for this driver crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
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
}

