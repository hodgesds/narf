//! virtio-fs-pci smokes — clean-room, sourced from VirtIO 1.2 §5.11
//! (transport + device-specific config).
//!
//! Stage 1: PCI registry contains 1AF4:105A; pure-data decoder for
//!   the device-specific config struct (§5.11.4 — tag[36] +
//!   num_request_queues u32 LE).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    decode_device_config, FsConfig, FS_TAG_LEN,
    VIRTIO_FS_PCI_DEVICE, VIRTIO_FS_PCI_VENDOR,
};

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_virtio_fs_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m|
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: VIRTIO_FS_PCI_VENDOR, device: VIRTIO_FS_PCI_DEVICE,
        }));
    if !matched {
        return TestResult::Fail("virtio-fs PCI match table missing 1AF4:105A");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/fs_pci", smoke_virtio_fs_pci_match_table);

// ── Stage 1: device-specific config decode (§5.11.4) ───────────────

fn smoke_virtio_fs_pci_config_decode() -> TestResult {
    // Build a 40-byte buffer: tag = "myfs\0\0...", num_request_queues = 4.
    let mut buf = [0u8; FS_TAG_LEN + 4];
    buf[0] = b'm'; buf[1] = b'y'; buf[2] = b'f'; buf[3] = b's';
    // num_request_queues = 4 (little-endian).
    buf[FS_TAG_LEN]     = 0x04;
    buf[FS_TAG_LEN + 1] = 0x00;
    buf[FS_TAG_LEN + 2] = 0x00;
    buf[FS_TAG_LEN + 3] = 0x00;
    let cfg: FsConfig = match decode_device_config(&buf) {
        Some(c) => c,
        None    => return TestResult::Fail("decode returned None on 40-byte input"),
    };
    if cfg.tag_len != 4         { return TestResult::Fail("tag_len != 4"); }
    if cfg.tag_str() != Some("myfs") {
        return TestResult::Fail("tag_str round-trip mismatch");
    }
    if cfg.num_request_queues != 4 {
        return TestResult::Fail("num_request_queues != 4");
    }
    // Short slice rejection.
    if decode_device_config(&buf[..FS_TAG_LEN + 3]).is_some() {
        return TestResult::Fail("decode accepted short slice");
    }
    // Full-width tag (no NUL) — tag_len = FS_TAG_LEN.
    let mut full = [b'A'; FS_TAG_LEN + 4];
    full[FS_TAG_LEN]     = 0;
    full[FS_TAG_LEN + 1] = 0;
    full[FS_TAG_LEN + 2] = 0;
    full[FS_TAG_LEN + 3] = 0;
    let cfg2 = decode_device_config(&full).unwrap();
    if cfg2.tag_len != FS_TAG_LEN {
        return TestResult::Fail("full-width tag should have tag_len = FS_TAG_LEN");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/fs_pci", smoke_virtio_fs_pci_config_decode);
