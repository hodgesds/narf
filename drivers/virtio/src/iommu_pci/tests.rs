//! virtio-iommu-pci smokes — clean-room, sourced from VirtIO 1.2 §5.16.
//!
//! Stage 1: PCI match table + §5.16.4 device-cfg decode round-trip.
//! Stage 2: §5.16.6 request encode/decode round-trips.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    IommuDeviceConfig, VIRTIO_IOMMU_PCI_DEVICE, VIRTIO_IOMMU_PCI_VENDOR,
};

// ── Stage 1: PCI match + device-cfg decode ─────────────────────────

fn smoke_virtio_iommu_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m|
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: VIRTIO_IOMMU_PCI_VENDOR,
            device: VIRTIO_IOMMU_PCI_DEVICE,
        }));
    if !matched {
        return TestResult::Fail("virtio-iommu PCI match table missing 1AF4:1057");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/iommu_pci", smoke_virtio_iommu_pci_match_table);

fn smoke_virtio_iommu_pci_config_decode() -> TestResult {
    // Synthesised §5.16.4 wire image. Decode → re-encode must
    // reproduce the bytes verbatim.
    let cfg = IommuDeviceConfig {
        page_size_mask:     0x0000_0000_0000_F000, // 4 KiB only
        input_range_start:  0x0000_0000_0000_0000,
        input_range_end:    0x0000_FFFF_FFFF_FFFF,
        domain_range_start: 0,
        domain_range_end:   0xFFFF,
        probe_size:         64,
    };
    let bytes = cfg.encode();
    if bytes.len() != IommuDeviceConfig::WIRE_SIZE {
        return TestResult::Fail("encode wire size mismatch");
    }
    let back = match IommuDeviceConfig::decode(&bytes) {
        Some(c) => c,
        None    => return TestResult::Fail("decode returned None"),
    };
    if back != cfg {
        return TestResult::Fail("config round-trip mismatch");
    }
    // Spot-check LE byte ordering of `probe_size` at +0x20.
    if bytes[0x20] != 64 || bytes[0x21] != 0 || bytes[0x22] != 0 || bytes[0x23] != 0 {
        return TestResult::Fail("probe_size LE encoding wrong");
    }
    // Short slice → None.
    if IommuDeviceConfig::decode(&bytes[..0x20]).is_some() {
        return TestResult::Fail("decode accepted short slice");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/iommu_pci", smoke_virtio_iommu_pci_config_decode);
