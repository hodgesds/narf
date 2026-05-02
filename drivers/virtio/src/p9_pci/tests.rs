//! virtio-9p smokes — clean room (VirtIO 1.2 §5.9 + 9P2000.L spec).

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    MountTag, MountTagDecodeError,
    VIRTIO_9P_PCI_DEVICE, VIRTIO_9P_PCI_VENDOR,
};

// ── Stage 1 ────────────────────────────────────────────────────────

fn smoke_p9_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m|
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: VIRTIO_9P_PCI_VENDOR, device: VIRTIO_9P_PCI_DEVICE,
        }));
    if !matched {
        return TestResult::Fail("virtio-9p PCI match table missing entry");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_match_table);

fn smoke_p9_mount_tag_decode() -> TestResult {
    // VirtIO 1.2 §5.9.4: u16 LE length followed by `length` bytes.
    let tag = b"hostshare";
    let mut wire: Vec<u8> = Vec::new();
    wire.extend_from_slice(&(tag.len() as u16).to_le_bytes());
    wire.extend_from_slice(tag);
    let mt = match MountTag::decode(&wire) {
        Ok(m)  => m,
        Err(_) => return TestResult::Fail("decode failed"),
    };
    if mt.tag != tag {
        return TestResult::Fail("mount tag bytes mismatch");
    }
    if mt.encode() != wire {
        return TestResult::Fail("round-trip mismatch");
    }
    // Empty tag is valid.
    let empty = vec![0u8, 0u8];
    match MountTag::decode(&empty) {
        Ok(m) if m.tag.is_empty() => {}
        _ => return TestResult::Fail("empty-tag decode failed"),
    }
    // Truncated buffer: 1 byte (need 2 for len).
    if MountTag::decode(&[0u8]) != Err(MountTagDecodeError::TooShortForLen) {
        return TestResult::Fail("expected TooShortForLen");
    }
    // Length says 5 but only 3 bytes follow.
    let bad = [5u8, 0, b'a', b'b', b'c'];
    if MountTag::decode(&bad) != Err(MountTagDecodeError::TooShortForTag) {
        return TestResult::Fail("expected TooShortForTag");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_mount_tag_decode);
