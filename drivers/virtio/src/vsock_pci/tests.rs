//! virtio-vsock-pci smokes — clean-room, sourced from VirtIO 1.2 §5.10.
//!
//! Stage 1: PCI match table + §5.10.4 device-cfg decode round-trip.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    VsockDeviceConfig,
    VIRTIO_VSOCK_PCI_DEVICE, VIRTIO_VSOCK_PCI_VENDOR,
};

// ── Stage 1: PCI match + device-cfg decode ─────────────────────────

fn smoke_virtio_vsock_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m|
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: VIRTIO_VSOCK_PCI_VENDOR,
            device: VIRTIO_VSOCK_PCI_DEVICE,
        }));
    if !matched {
        return TestResult::Fail("virtio-vsock PCI match table missing 1AF4:1053");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_match_table);

fn smoke_virtio_vsock_pci_config_decode() -> TestResult {
    let cfg = VsockDeviceConfig { guest_cid: 0x0000_0000_0000_0003 };
    let bytes = cfg.encode();
    if bytes.len() != VsockDeviceConfig::WIRE_SIZE {
        return TestResult::Fail("encode wire size mismatch");
    }
    // §5.10.4 guest_cid is u64 LE at +0x00.
    if bytes[0] != 0x03 || bytes[1] != 0 || bytes[2] != 0 || bytes[3] != 0 {
        return TestResult::Fail("guest_cid LE encoding wrong (low)");
    }
    if bytes[4] != 0 || bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0 {
        return TestResult::Fail("guest_cid LE encoding wrong (high)");
    }
    let back = match VsockDeviceConfig::decode(&bytes) {
        Some(c) => c,
        None    => return TestResult::Fail("decode returned None"),
    };
    if back != cfg {
        return TestResult::Fail("config round-trip mismatch");
    }
    // Larger CID — exercise the full 8 bytes.
    let cfg = VsockDeviceConfig { guest_cid: 0xCAFE_F00D_DEAD_BEEF };
    let bytes = cfg.encode();
    let want = 0xCAFE_F00D_DEAD_BEEFu64.to_le_bytes();
    if bytes != want {
        return TestResult::Fail("guest_cid full LE bytes wrong");
    }
    if VsockDeviceConfig::decode(&bytes) != Some(cfg) {
        return TestResult::Fail("large guest_cid round-trip");
    }
    // Short slice → None.
    if VsockDeviceConfig::decode(&bytes[..7]).is_some() {
        return TestResult::Fail("decode accepted short slice");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_config_decode);
