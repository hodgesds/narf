//! iwlwifi smokes — co-located with the driver per project
//! convention. Stage 1 covers PCI match-table registration only;
//! live bring-up is blocked on public register-map docs.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    register_pci_driver, IWL_DEV_AX200, IWL_DEV_AX201, IWL_DEV_AX210, IWL_DEV_AX211, IWL_VENDOR,
};

fn smoke_iwlwifi_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();
    let want = [IWL_DEV_AX200, IWL_DEV_AX201, IWL_DEV_AX210, IWL_DEV_AX211];
    for did in want {
        let matched = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: IWL_VENDOR, device,
            } if device == did)
        });
        if !matched {
            return TestResult::Fail("iwlwifi PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/iwlwifi", smoke_iwlwifi_pci_match_table);
