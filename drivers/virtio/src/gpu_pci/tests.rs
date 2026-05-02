//! virtio-gpu-pci smokes — clean-room, sourced from VirtIO 1.2 §5.7.
//!
//! Stage 1: PCI match table contains both transitional ids
//!   (1AF4:1050 modern, 1AF4:1010 legacy).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    VIRTIO_GPU_PCI_DEVICE, VIRTIO_GPU_PCI_DEVICE_LEGACY, VIRTIO_GPU_PCI_VENDOR,
};

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_virtio_gpu_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let want = [VIRTIO_GPU_PCI_DEVICE, VIRTIO_GPU_PCI_DEVICE_LEGACY];
    for did in want {
        let matched = registered.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: VIRTIO_GPU_PCI_VENDOR, device,
            } if device == did));
        if !matched {
            return TestResult::Fail("virtio-gpu PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/gpu_pci", smoke_virtio_gpu_pci_match_table);
