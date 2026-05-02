//! virtio-fs-pci smokes — clean-room, sourced from VirtIO 1.2 §5.11
//! (transport + device-specific config) and the public FUSE
//! wire-protocol docs (in-header layout + opcode numbers).
//!
//! Stage 1: PCI registry contains 1AF4:105A; pure-data decoder for
//!   the device-specific config struct (§5.11.4 — tag[36] +
//!   num_request_queues u32 LE).
//! Stage 2: `fuse_in_header` round-trip through encode/decode +
//!   opcode numeric values.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    decode_device_config, FsConfig, FuseInHeader, FuseOpcode,
    FS_TAG_LEN, FUSE_GETATTR, FUSE_INIT, FUSE_IN_HEADER_LEN,
    FUSE_LOOKUP, FUSE_READ, FUSE_RELEASE,
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

// ── Stage 2: fuse_in_header round-trip + opcode numeric values ─────

fn smoke_virtio_fs_pci_fuse_in_header_roundtrip() -> TestResult {
    // Numeric opcode values per the FUSE wire-protocol docs.
    if FUSE_LOOKUP  != 1  { return TestResult::Fail("FUSE_LOOKUP  != 1"); }
    if FUSE_GETATTR != 3  { return TestResult::Fail("FUSE_GETATTR != 3"); }
    if FUSE_READ    != 15 { return TestResult::Fail("FUSE_READ    != 15"); }
    if FUSE_RELEASE != 18 { return TestResult::Fail("FUSE_RELEASE != 18"); }
    if FUSE_INIT    != 26 { return TestResult::Fail("FUSE_INIT    != 26"); }
    if FuseOpcode::Lookup  as u32 != FUSE_LOOKUP  { return TestResult::Fail("Lookup enum"); }
    if FuseOpcode::Getattr as u32 != FUSE_GETATTR { return TestResult::Fail("Getattr enum"); }
    if FuseOpcode::Read    as u32 != FUSE_READ    { return TestResult::Fail("Read enum"); }
    if FuseOpcode::Release as u32 != FUSE_RELEASE { return TestResult::Fail("Release enum"); }
    if FuseOpcode::Init    as u32 != FUSE_INIT    { return TestResult::Fail("Init enum"); }

    // Header length sanity.
    if FUSE_IN_HEADER_LEN != 40 {
        return TestResult::Fail("FUSE_IN_HEADER_LEN != 40");
    }

    // Build → encode → decode → expect equality.
    let payload_len = 12u32;
    let h = FuseInHeader::new(
        FuseOpcode::Lookup,
        /*unique*/ 0xDEAD_BEEF_CAFE_F00D,
        /*nodeid*/ 1, // FUSE_ROOT_ID
        /*uid*/ 1000,
        /*gid*/ 1000,
        /*pid*/ 4242,
        payload_len,
    );
    if h.len != FUSE_IN_HEADER_LEN as u32 + payload_len {
        return TestResult::Fail("header.len != hdr + payload");
    }
    let bytes = h.encode();
    if bytes.len() != FUSE_IN_HEADER_LEN {
        return TestResult::Fail("encode produced wrong byte count");
    }
    // Spot-check that little-endian encoding placed opcode at offset 4.
    if u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != FUSE_LOOKUP {
        return TestResult::Fail("encoded opcode not at offset 4 LE");
    }
    if u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    ]) != 0xDEAD_BEEF_CAFE_F00D {
        return TestResult::Fail("encoded unique not at offset 8 LE");
    }
    let decoded = match FuseInHeader::decode(&bytes) {
        Some(d) => d,
        None    => return TestResult::Fail("decode of 40-byte buf returned None"),
    };
    if decoded != h {
        return TestResult::Fail("encode/decode round-trip mismatch");
    }
    if FuseInHeader::decode(&bytes[..FUSE_IN_HEADER_LEN - 1]).is_some() {
        return TestResult::Fail("decode accepted short slice");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/fs_pci", smoke_virtio_fs_pci_fuse_in_header_roundtrip);
