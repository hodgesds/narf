//! Per-driver smoke tests for `narf-drivers-platform`.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── SMBus ──────────────────────────────────────────────────────────

fn smoke_smbus_class_match_registered() -> TestResult {
    use crate::smbus;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    smbus::register_pci_driver();
    let regs = registered_pci_drivers();
    let has = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::Class {
                class: 0x0C,
                mask: 0xFF
            }
        )
    });
    if !has {
        return TestResult::Fail("smbus class match missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/smbus", smoke_smbus_class_match_registered);

    fn smoke_acpi_ec_discovery() -> TestResult {
    use crate::ec;
    if ec::with_ec(|_| {}).is_some() {
        TestResult::Pass
    } else {
        TestResult::Skip("ACPI EC not found (not a laptop config?)")
    }
    }
    kernel_test_in!("drivers/platform/ec", smoke_acpi_ec_discovery);


// ── TPM ────────────────────────────────────────────────────────────

fn smoke_tpm_init_default() -> TestResult {
    use crate::tpm;
    tpm::__reset_for_test();
    tpm::try_init_default();
    // Probe doesn't require a TPM to exist; if one isn't present,
    // we just want the no-op path to not panic.
    if tpm::is_present() {
        // Sanity: kind() should match what probe surfaced.
        let k = tpm::kind();
        if k.is_none() {
            return TestResult::Fail("tpm present but kind() = None");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/tpm", smoke_tpm_init_default);
