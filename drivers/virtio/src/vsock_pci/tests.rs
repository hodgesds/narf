//! virtio-vsock-pci smokes — clean-room, sourced from VirtIO 1.2 §5.10.
//!
//! Stage 1: PCI match table + §5.10.4 device-cfg decode round-trip.
//! Stage 2: §5.10.6 `virtio_vsock_hdr` round-trips per `VsockOp`.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    VsockDeviceConfig, VsockHdr, VsockOp,
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

// ── Stage 2: §5.10.6 virtio_vsock_hdr round-trips ──────────────────

fn smoke_virtio_vsock_pci_op_values() -> TestResult {
    // §5.10.6 fixes the op numbers; pin them here.
    if VsockOp::Request       as u16 != 1 { return TestResult::Fail("REQUEST != 1"); }
    if VsockOp::Response      as u16 != 2 { return TestResult::Fail("RESPONSE != 2"); }
    if VsockOp::Rst           as u16 != 3 { return TestResult::Fail("RST != 3"); }
    if VsockOp::Shutdown      as u16 != 4 { return TestResult::Fail("SHUTDOWN != 4"); }
    if VsockOp::Rw            as u16 != 5 { return TestResult::Fail("RW != 5"); }
    if VsockOp::CreditUpdate  as u16 != 6 { return TestResult::Fail("CREDIT_UPDATE != 6"); }
    if VsockOp::CreditRequest as u16 != 7 { return TestResult::Fail("CREDIT_REQUEST != 7"); }
    for v in [1u16, 2, 3, 4, 5, 6, 7] {
        match VsockOp::from_raw(v) {
            Some(op) if op as u16 == v => {}
            _ => return TestResult::Fail("from_raw round-trip failed"),
        }
    }
    if VsockOp::from_raw(0).is_some() { return TestResult::Fail("from_raw(0) not None"); }
    if VsockOp::from_raw(8).is_some() { return TestResult::Fail("from_raw(8) not None"); }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_op_values);

fn hdr_with(op: VsockOp) -> VsockHdr {
    VsockHdr {
        src_cid:   0x0000_0000_0000_0003,
        dst_cid:   0xFFFF_FFFF_0000_0002,
        src_port:  0x1111_2222,
        dst_port:  0x3333_4444,
        len:       0xDEAD_BEEF,
        typ:       VsockHdr::TYPE_STREAM,
        op,
        flags:     0xA5A5_5A5A,
        buf_alloc: 0x0001_0000,
        fwd_cnt:   0x0000_4242,
    }
}

fn check_hdr_layout(h: &VsockHdr) -> Option<&'static str> {
    let bytes = h.encode();
    if bytes.len() != VsockHdr::WIRE_SIZE { return Some("hdr wire size"); }
    // Spot-check spec-mandated offsets (§5.10.6).
    if bytes[0x00..0x08] != h.src_cid.to_le_bytes()  { return Some("src_cid LE @ +0x00"); }
    if bytes[0x08..0x10] != h.dst_cid.to_le_bytes()  { return Some("dst_cid LE @ +0x08"); }
    if bytes[0x10..0x14] != h.src_port.to_le_bytes() { return Some("src_port LE @ +0x10"); }
    if bytes[0x14..0x18] != h.dst_port.to_le_bytes() { return Some("dst_port LE @ +0x14"); }
    if bytes[0x18..0x1C] != h.len.to_le_bytes()      { return Some("len LE @ +0x18"); }
    if bytes[0x1C..0x1E] != h.typ.to_le_bytes()      { return Some("type LE @ +0x1C"); }
    if bytes[0x1E..0x20] != (h.op as u16).to_le_bytes() {
        return Some("op LE @ +0x1E");
    }
    if bytes[0x20..0x24] != h.flags.to_le_bytes()    { return Some("flags LE @ +0x20"); }
    if bytes[0x24..0x28] != h.buf_alloc.to_le_bytes(){ return Some("buf_alloc LE @ +0x24"); }
    if bytes[0x28..0x2C] != h.fwd_cnt.to_le_bytes()  { return Some("fwd_cnt LE @ +0x28"); }
    let back = match VsockHdr::decode(&bytes) {
        Some(b) => b,
        None    => return Some("decode None"),
    };
    if back != *h { return Some("hdr round-trip"); }
    None
}

fn smoke_virtio_vsock_pci_hdr_request() -> TestResult {
    if let Some(e) = check_hdr_layout(&hdr_with(VsockOp::Request)) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_hdr_request);

fn smoke_virtio_vsock_pci_hdr_response() -> TestResult {
    if let Some(e) = check_hdr_layout(&hdr_with(VsockOp::Response)) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_hdr_response);

fn smoke_virtio_vsock_pci_hdr_rst() -> TestResult {
    if let Some(e) = check_hdr_layout(&hdr_with(VsockOp::Rst)) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_hdr_rst);

fn smoke_virtio_vsock_pci_hdr_shutdown() -> TestResult {
    if let Some(e) = check_hdr_layout(&hdr_with(VsockOp::Shutdown)) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_hdr_shutdown);

fn smoke_virtio_vsock_pci_hdr_rw() -> TestResult {
    if let Some(e) = check_hdr_layout(&hdr_with(VsockOp::Rw)) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_hdr_rw);

fn smoke_virtio_vsock_pci_hdr_credit_update() -> TestResult {
    if let Some(e) = check_hdr_layout(&hdr_with(VsockOp::CreditUpdate)) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_hdr_credit_update);

fn smoke_virtio_vsock_pci_hdr_credit_request() -> TestResult {
    if let Some(e) = check_hdr_layout(&hdr_with(VsockOp::CreditRequest)) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_hdr_credit_request);

fn smoke_virtio_vsock_pci_hdr_short_slice() -> TestResult {
    let bytes = hdr_with(VsockOp::Rw).encode();
    if VsockHdr::decode(&bytes[..VsockHdr::WIRE_SIZE - 1]).is_some() {
        return TestResult::Fail("decode accepted short slice");
    }
    // Unknown op byte → None.
    let mut tampered = bytes;
    tampered[0x1E] = 0; tampered[0x1F] = 0;
    if VsockHdr::decode(&tampered).is_some() {
        return TestResult::Fail("decode accepted op=0");
    }
    tampered[0x1E] = 8; tampered[0x1F] = 0;
    if VsockHdr::decode(&tampered).is_some() {
        return TestResult::Fail("decode accepted op=8");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/vsock_pci", smoke_virtio_vsock_pci_hdr_short_slice);
