//! virtio-iommu-pci smokes — clean-room, sourced from VirtIO 1.2 §5.16.
//!
//! Stage 1: PCI match table + §5.16.4 device-cfg decode round-trip.
//! Stage 2: §5.16.6 request encode/decode round-trips.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    IommuDeviceConfig, IommuOp, ReqAttach, ReqDetach, ReqHeader, ReqMap, ReqUnmap,
    VIRTIO_IOMMU_PCI_DEVICE, VIRTIO_IOMMU_PCI_VENDOR,
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

// ── Stage 2: §5.16.6 request encode/decode round-trips ─────────────

fn smoke_virtio_iommu_pci_opcode_values() -> TestResult {
    // §5.16.6 fixes the opcode numbers; pin them here.
    if IommuOp::Attach as u8 != 1 { return TestResult::Fail("ATTACH != 1"); }
    if IommuOp::Detach as u8 != 2 { return TestResult::Fail("DETACH != 2"); }
    if IommuOp::Map    as u8 != 3 { return TestResult::Fail("MAP != 3"); }
    if IommuOp::Unmap  as u8 != 4 { return TestResult::Fail("UNMAP != 4"); }
    if IommuOp::Probe  as u8 != 5 { return TestResult::Fail("PROBE != 5"); }
    for v in [1u8, 2, 3, 4, 5] {
        match IommuOp::from_raw(v) {
            Some(op) if op as u8 == v => {}
            _ => return TestResult::Fail("from_raw round-trip failed"),
        }
    }
    if IommuOp::from_raw(0).is_some() { return TestResult::Fail("from_raw(0) not None"); }
    if IommuOp::from_raw(6).is_some() { return TestResult::Fail("from_raw(6) not None"); }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/iommu_pci", smoke_virtio_iommu_pci_opcode_values);

fn smoke_virtio_iommu_pci_req_attach_roundtrip() -> TestResult {
    let req = ReqAttach { domain: 0xDEAD_BEEF, endpoint: 0x1234_5678 };
    let bytes = req.encode(0xA5A5_5A5A);
    if bytes.len() != ReqAttach::WIRE_SIZE {
        return TestResult::Fail("attach wire size");
    }
    if bytes[0] != IommuOp::Attach as u8 {
        return TestResult::Fail("attach opcode byte");
    }
    let (h, back) = match ReqAttach::decode(&bytes) {
        Some(t) => t,
        None    => return TestResult::Fail("attach decode None"),
    };
    if h.op != IommuOp::Attach || h.flags != 0xA5A5_5A5A {
        return TestResult::Fail("attach header round-trip");
    }
    if back != req {
        return TestResult::Fail("attach payload round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/iommu_pci", smoke_virtio_iommu_pci_req_attach_roundtrip);

fn smoke_virtio_iommu_pci_req_detach_roundtrip() -> TestResult {
    let req = ReqDetach { domain: 0x0000_0042, endpoint: 0xCAFE_F00D };
    let bytes = req.encode(0);
    if bytes.len() != ReqDetach::WIRE_SIZE {
        return TestResult::Fail("detach wire size");
    }
    if bytes[0] != IommuOp::Detach as u8 {
        return TestResult::Fail("detach opcode byte");
    }
    let (h, back) = match ReqDetach::decode(&bytes) {
        Some(t) => t,
        None    => return TestResult::Fail("detach decode None"),
    };
    if h.op != IommuOp::Detach || h.flags != 0 {
        return TestResult::Fail("detach header round-trip");
    }
    if back != req {
        return TestResult::Fail("detach payload round-trip");
    }
    // Cross-op rejection: an Attach-encoded blob must not decode as Detach.
    let attach_bytes = ReqAttach { domain: 1, endpoint: 2 }.encode(0);
    if ReqDetach::decode(&attach_bytes).is_some() {
        return TestResult::Fail("detach decoded an attach blob");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/iommu_pci", smoke_virtio_iommu_pci_req_detach_roundtrip);

fn smoke_virtio_iommu_pci_req_map_roundtrip() -> TestResult {
    let req = ReqMap {
        domain:     7,
        virt_start: 0x0000_1000_0000_0000,
        virt_end:   0x0000_1000_0000_0FFF,
        phys_start: 0x0000_0000_8000_0000,
        map_flags:  0b0000_0111, // READ|WRITE|EXEC
    };
    let bytes = req.encode(0x1);
    if bytes.len() != ReqMap::WIRE_SIZE {
        return TestResult::Fail("map wire size");
    }
    if bytes[0] != IommuOp::Map as u8 {
        return TestResult::Fail("map opcode byte");
    }
    let (h, back) = match ReqMap::decode(&bytes) {
        Some(t) => t,
        None    => return TestResult::Fail("map decode None"),
    };
    if h.op != IommuOp::Map || h.flags != 0x1 {
        return TestResult::Fail("map header round-trip");
    }
    if back != req {
        return TestResult::Fail("map payload round-trip");
    }
    // Spot-check that virt_start lands at +0x18 (header=16 + domain=4 + resv=4).
    let want = 0x0000_1000_0000_0000u64.to_le_bytes();
    if bytes[0x18..0x20] != want {
        return TestResult::Fail("map virt_start offset");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/iommu_pci", smoke_virtio_iommu_pci_req_map_roundtrip);

fn smoke_virtio_iommu_pci_req_unmap_roundtrip() -> TestResult {
    let req = ReqUnmap {
        domain:     7,
        virt_start: 0x0000_1000_0000_0000,
        virt_end:   0x0000_1000_0000_0FFF,
    };
    let bytes = req.encode(0);
    if bytes.len() != ReqUnmap::WIRE_SIZE {
        return TestResult::Fail("unmap wire size");
    }
    if bytes[0] != IommuOp::Unmap as u8 {
        return TestResult::Fail("unmap opcode byte");
    }
    let (h, back) = match ReqUnmap::decode(&bytes) {
        Some(t) => t,
        None    => return TestResult::Fail("unmap decode None"),
    };
    if h.op != IommuOp::Unmap || h.flags != 0 {
        return TestResult::Fail("unmap header round-trip");
    }
    if back != req {
        return TestResult::Fail("unmap payload round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/iommu_pci", smoke_virtio_iommu_pci_req_unmap_roundtrip);

fn smoke_virtio_iommu_pci_req_header_roundtrip() -> TestResult {
    for op in [IommuOp::Attach, IommuOp::Detach, IommuOp::Map,
               IommuOp::Unmap, IommuOp::Probe]
    {
        let h = ReqHeader { op, flags: 0xDEAD_BEEF };
        let bytes = h.encode();
        if bytes.len() != ReqHeader::WIRE_SIZE {
            return TestResult::Fail("header wire size");
        }
        if bytes[0] != op as u8 { return TestResult::Fail("header op byte"); }
        // Reserved bytes 1..4 must be zero.
        if bytes[1] != 0 || bytes[2] != 0 || bytes[3] != 0 {
            return TestResult::Fail("header reserved nonzero");
        }
        let back = match ReqHeader::decode(&bytes) {
            Some(h) => h,
            None    => return TestResult::Fail("header decode None"),
        };
        if back != h { return TestResult::Fail("header round-trip"); }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/iommu_pci", smoke_virtio_iommu_pci_req_header_roundtrip);
