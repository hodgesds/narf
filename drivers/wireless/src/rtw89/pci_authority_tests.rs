//! A real epoch revocation must fail before diagnostic BAR/config access.
use super::{pci, REALTEK_VENDOR, RTL_DEV_8852AE};
use narf_bus::{BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, PcieAddr};
use narf_capabilities::{Cap, Write};
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_revoked_diagnostic_cannot_touch_pci() -> TestResult {
    let address = PcieAddr::new(0, 0, 7, 0);
    let device = BusDevice {
        addr: BusAddr::Pcie(address),
        id: DeviceId {
            vendor: REALTEK_VENDOR,
            device: RTL_DEV_8852AE,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: address,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    cap.revoke();
    // SAFETY: this test is the sole owner of its private diagnostic fixture;
    // current authority must reject before the deliberately unmapped config.
    let result = unsafe { pci::bring_up(&device, &cap) };
    if !matches!(result, Err(pci::ProbeError::PciAccess)) {
        return TestResult::Fail("revoked diagnostic entered PCI/BAR preparation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_revoked_diagnostic_cannot_touch_pci
);
