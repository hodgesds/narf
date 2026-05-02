//! virtio-scsi-pci smokes — clean-room, sourced from VirtIO 1.2 §5.6.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{VIRTIO_SCSI_PCI_DEVICE, VIRTIO_SCSI_PCI_VENDOR};

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_virtio_scsi_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m|
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: VIRTIO_SCSI_PCI_VENDOR,
            device: VIRTIO_SCSI_PCI_DEVICE,
        }));
    if !matched {
        return TestResult::Fail("virtio-scsi PCI match table missing 1AF4:1048");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/scsi_pci", smoke_virtio_scsi_pci_match_table);
