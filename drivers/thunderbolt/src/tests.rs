//! Stage-0 smokes for the Thunderbolt / USB4 NHI driver. Mirrors the
//! VMD Stage-0 smoke shape: match-table coverage, synthetic-device
//! specificity check, rejects unrelated Intel devices, register-block
//! layout sanity vs. Linux constants, and a `not-present` trace for
//! the QEMU TCG smoke target (no USB4 model on q35).

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_tb_register_all_known_ids() -> TestResult {
    // Every known Thunderbolt device ID must land in the match
    // table as an exact VendorDevice entry — class match (USB4
    // host = 0x0C0340) alone is too coarse on AMD silicon which
    // ships a different controller family at the same class.
    use crate::nhi;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    nhi::register_pci_driver_thunderbolt();
    let regs = registered_pci_drivers();
    for (did, _name) in nhi::TB_DEVICE_IDS.iter().copied() {
        let has = regs.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: nhi::INTEL_VENDOR,
                    device,
                } if device == did
            )
        });
        if !has {
            return TestResult::Fail("thunderbolt: missing VendorDevice match for known DID");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/nhi", smoke_tb_register_all_known_ids);

fn smoke_tb_match_kind_matches_synthetic_tgl() -> TestResult {
    // Build a synthetic BusDevice with the Tiger Lake NHI ID
    // (0x9A1B — the user's "Maple Ridge" entry) and confirm at
    // least one registered entry claims it at full specificity.
    // Guards against a future regression that downgrades the
    // matcher to a class backstop and silently weakens binding.
    use crate::nhi;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
    use narf_memory::PhysAddr;
    __reset_for_test();
    nhi::register_pci_driver_thunderbolt();
    let addr = PcieAddr::new(0, 0, 0x0D, 0); // TGL NHI typically 00:0d.0
    let synth = BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor: nhi::INTEL_VENDOR,
            device: 0x9A1B,
            class: 0x0C0340,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(0),
        },
    };
    let regs = registered_pci_drivers();
    let mut matched = 0;
    let mut best_specificity = 0u8;
    for m in &regs {
        if m.kind.matches(&synth) {
            matched += 1;
            if m.kind.specificity() > best_specificity {
                best_specificity = m.kind.specificity();
            }
        }
    }
    if matched == 0 {
        return TestResult::Fail("thunderbolt: synthetic 9A1B not matched");
    }
    if best_specificity != 3 {
        return TestResult::Fail("thunderbolt: best match must be VendorDevice (specificity 3)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/nhi",
    smoke_tb_match_kind_matches_synthetic_tgl
);

fn smoke_tb_rejects_unrelated_intel_device() -> TestResult {
    // Probe with the AHCI ICH9 device ID — also vendor 0x8086 —
    // and confirm the TB probe rejects it via `NotForThisDriver`,
    // not a more generic `BadDevice`. Keeps the probe trace clean
    // on real silicon where a class backstop would otherwise drag
    // every Intel device through the Thunderbolt probe path.
    use crate::nhi;
    use narf_bus::{BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, PcieAddr, ProbeError};
    use narf_capabilities::Cap;
    use narf_memory::PhysAddr;
    let addr = PcieAddr::new(0, 0, 0x1F, 2);
    let dev = BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor: 0x8086,
            device: 0x2922, // ICH9 AHCI — definitively not a TB ID
            class: 0x010601,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(0),
        },
    };
    let cap = Cap::<BusDeviceCap, narf_capabilities::Write>::bootstrap();
    match nhi::probe(dev, cap) {
        Err(ProbeError::NotForThisDriver) => TestResult::Pass,
        Err(_) => TestResult::Fail("thunderbolt: non-TB device rejected with wrong error"),
        Ok(_) => TestResult::Fail("thunderbolt: probe must not claim non-TB devices"),
    }
}
kernel_test_in!(
    "drivers/thunderbolt/nhi",
    smoke_tb_rejects_unrelated_intel_device
);

fn smoke_tb_reg_caps_layout_matches_linux() -> TestResult {
    // Sanity-check the REG_CAPS register layout against the Linux
    // header. Catches a future edit that accidentally shifts the
    // version byte or the hop-count mask out of agreement with
    // `drivers/thunderbolt/nhi_regs.h`.
    use crate::nhi;
    if nhi::REG_CAPS != 0x39640 {
        return TestResult::Fail("thunderbolt: REG_CAPS offset mismatch");
    }
    if nhi::REG_CAPS_VERSION_MASK != 0x00FF_0000 {
        return TestResult::Fail("thunderbolt: REG_CAPS version mask mismatch");
    }
    if nhi::REG_CAPS_VERSION_SHIFT != 16 {
        return TestResult::Fail("thunderbolt: REG_CAPS version shift mismatch");
    }
    if nhi::REG_CAPS_HOP_COUNT_MASK != 0x0000_07FF {
        return TestResult::Fail("thunderbolt: REG_CAPS hop count mask mismatch");
    }
    // Compose a synthetic REG_CAPS word: version = 0x40, hops = 12.
    let synth: u32 = (0x40u32 << 16) | 12u32;
    let v = ((synth & nhi::REG_CAPS_VERSION_MASK) >> nhi::REG_CAPS_VERSION_SHIFT) as u8;
    let h = (synth & nhi::REG_CAPS_HOP_COUNT_MASK) as u16;
    if v != 0x40 || h != 12 {
        return TestResult::Fail("thunderbolt: REG_CAPS decode round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/nhi",
    smoke_tb_reg_caps_layout_matches_linux
);

fn smoke_tb_sku_name_round_trip() -> TestResult {
    // Each known DID must round-trip through `sku_name`, and an
    // unknown DID must return None. Stage-0 announce relies on
    // this lookup; a silent regression would print
    // "intel-tb-unknown" for every device on real HW.
    use crate::nhi;
    for (did, name) in nhi::TB_DEVICE_IDS.iter().copied() {
        match nhi::sku_name(did) {
            Some(n) if n == name => {}
            _ => return TestResult::Fail("thunderbolt: sku_name lookup miss"),
        }
    }
    if nhi::sku_name(0xFFFF).is_some() {
        return TestResult::Fail("thunderbolt: sku_name accepted unknown DID");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/nhi", smoke_tb_sku_name_round_trip);

fn smoke_tb_covers_user_cited_ids() -> TestResult {
    // Explicit assertion that the device IDs from the bring-up
    // brief land in the table: the user-cited 9A1B / 9A1D (TGL),
    // 463F / 466D (ADL), 7EB3 (RPL-P / MTL-M variant), and 5781
    // (Barlow Ridge 80G). If any one of these drops out, real
    // HW probably regresses silently.
    use crate::nhi;
    for did in [0x9A1Bu16, 0x9A1D, 0x463F, 0x466D, 0x7EB3, 0x5781] {
        if nhi::sku_name(did).is_none() {
            return TestResult::Fail("thunderbolt: brief-cited DID missing from table");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/nhi", smoke_tb_covers_user_cited_ids);

fn smoke_tb_not_present_on_qemu_tcg() -> TestResult {
    // QEMU TCG q35 doesn't model a USB4 NHI. Verify the bus
    // enumeration doesn't surface one (defensive — would catch
    // any future QEMU update that started emulating one without
    // us updating the smokes). Counter-evidence smoke that proves
    // the match table is alive (would fire on real HW) without
    // requiring a positive detection on the QEMU smoke target.
    use crate::nhi;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{devices, BusKind};
    // SAFETY: the QEMU q35 smoke target maps PCIe ECAM at the default base;
    // init() only reads the config space mapped there during enumeration.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_tb = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == nhi::INTEL_VENDOR
            && nhi::TB_DEVICE_IDS
                .iter()
                .any(|(did, _)| *did == d.id.device)
    });
    if has_tb {
        return TestResult::Skip(
            "thunderbolt present (real-HW path); positive smoke is a follow-up",
        );
    }
    if nhi::instance_count() != 0 {
        nhi::__reset_for_test();
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/nhi", smoke_tb_not_present_on_qemu_tcg);

// ── Stage-1 smokes ─────────────────────────────────────────────────
//
// Cover the three units Stage-1 adds: control-packet encode (`cm.rs`),
// adapter-type decode (`adapter.rs`), and the route-string +
// topology walker (`switch.rs`). All three are pure-logic so no MMIO
// substrate is required — the walker drives a closure-backed
// `TopologyProbe` populated from an in-memory tree.

fn smoke_cm_header_encode_round_trip() -> TestResult {
    // Encode then decode a representative header. Catches a bit-
    // field regression (route_hi mask, unknown-field position) on
    // the first byte that hits the wire on a real control packet.
    use crate::cm::Header;
    let h = Header {
        // 54-bit max-width route: low 32 bits = 0xDEAD_BEEF, high 22
        // bits = 0x2A_BABE (10 hex digits = 22 bits since the leading
        // byte 0x2A is 6 bits + the next two bytes fill the rest).
        route: ((0x2A_BABE_u64 & 0x003F_FFFF) << 32) | 0xDEAD_BEEF,
        unknown: 0x123,
    };
    let words = h.encode();
    let d = Header::decode(words);
    if d != h {
        return TestResult::Fail("thunderbolt: header encode/decode mismatch");
    }
    // The unknown field must not bleed into route_hi: encode with
    // unknown = 0 + a max-route, then encode with unknown = 0x3FF +
    // route = 0 — the two dword 0 values must differ only in the
    // top 10 bits.
    let a = Header {
        route: Header::ROUTE_MAX,
        unknown: 0,
    }
    .encode()[0];
    let b = Header {
        route: 0,
        unknown: 0x3FF,
    }
    .encode()[0];
    if (a & 0xFFC0_0000) != 0 {
        return TestResult::Fail("thunderbolt: route_hi leaked into unknown");
    }
    if (b & 0x003F_FFFF) != 0 {
        return TestResult::Fail("thunderbolt: unknown leaked into route_hi");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/cm", smoke_cm_header_encode_round_trip);

fn smoke_cm_address_encode_round_trip() -> TestResult {
    // Address bit-field layout: offset[12:0] | length[18:13] |
    // port[24:19] | space[26:25] | seq[28:27] | zero[31:29].
    use crate::cm::{Address, CfgSpace};
    let cases = [
        Address {
            offset: 0,
            length: 1,
            port: 0,
            space: CfgSpace::Switch,
            seq: 0,
        },
        Address {
            offset: 0x1FFF,
            length: 0x3F,
            port: 0x3F,
            space: CfgSpace::Counters,
            seq: 3,
        },
        Address {
            offset: 0x123,
            length: 12,
            port: 5,
            space: CfgSpace::Port,
            seq: 1,
        },
    ];
    for c in cases {
        let dw = c.encode();
        // Bit 31..29 must be zero per the spec.
        if (dw & 0xE000_0000) != 0 {
            return TestResult::Fail("thunderbolt: address reserved bits non-zero");
        }
        let d = Address::decode(dw).ok_or(()).unwrap_or(Address {
            offset: 0,
            length: 0,
            port: 0,
            space: CfgSpace::Hops,
            seq: 0,
        });
        if d != c {
            return TestResult::Fail("thunderbolt: address encode/decode mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/cm", smoke_cm_address_encode_round_trip);

fn smoke_cm_cfg_read_encode_layout() -> TestResult {
    // Build a TB_CFG_PKG_READ for: route 0x0000_0100 (one hop, port 1
    // off host), port 3, space SWITCH, offset 0, length 8 dwords.
    // Verify the three on-wire dwords match what we computed by hand.
    use crate::cm::{encode_cfg_read, Address, CfgSpace, Header};
    let hdr = Header {
        route: 0x0100,
        unknown: 0,
    };
    let addr = Address {
        offset: 0,
        length: 8,
        port: 3,
        space: CfgSpace::Switch,
        seq: 0,
    };
    let mut buf = [0u32; 3];
    let len = match encode_cfg_read(hdr, addr, &mut buf) {
        Ok(l) => l,
        Err(_) => return TestResult::Fail("thunderbolt: encode_cfg_read failed"),
    };
    if len != 12 {
        return TestResult::Fail("thunderbolt: encode_cfg_read length wrong");
    }
    // dword 0: route_hi = 0 (high 22 bits of 0x100 are 0), unknown = 0.
    if buf[0] != 0 {
        return TestResult::Fail("thunderbolt: cfg_read dword 0 wrong");
    }
    // dword 1: route_lo = 0x100.
    if buf[1] != 0x100 {
        return TestResult::Fail("thunderbolt: cfg_read dword 1 wrong");
    }
    // dword 2: offset 0, length 8 << 13 = 0x10000, port 3 << 19 =
    // 0x180000, space SWITCH=2 << 25 = 0x0400_0000, seq 0.
    let expect_d2: u32 = (8u32 << 13) | (3u32 << 19) | (2u32 << 25);
    if buf[2] != expect_d2 {
        return TestResult::Fail("thunderbolt: cfg_read dword 2 wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/cm", smoke_cm_cfg_read_encode_layout);

fn smoke_cm_cfg_write_payload_check() -> TestResult {
    // A TB_CFG_PKG_WRITE with `length` ≠ payload.len() must fail.
    use crate::cm::{encode_cfg_write, Address, CfgSpace, CmError, Header};
    let hdr = Header {
        route: 0,
        unknown: 0,
    };
    let addr = Address {
        offset: 0,
        length: 4,
        port: 0,
        space: CfgSpace::Switch,
        seq: 0,
    };
    let payload_short: [u32; 2] = [0; 2];
    let payload_match: [u32; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
    let mut buf = [0u32; 16];
    match encode_cfg_write(hdr, addr, &payload_short, &mut buf) {
        Err(CmError::PayloadLengthMismatch) => {}
        _ => return TestResult::Fail("thunderbolt: short payload not rejected"),
    }
    let len = match encode_cfg_write(hdr, addr, &payload_match, &mut buf) {
        Ok(l) => l,
        Err(_) => return TestResult::Fail("thunderbolt: matching payload rejected"),
    };
    if len != 7 * 4 {
        return TestResult::Fail("thunderbolt: cfg_write length wrong");
    }
    if buf[3..7] != payload_match {
        return TestResult::Fail("thunderbolt: cfg_write payload mis-copied");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/cm", smoke_cm_cfg_write_payload_check);

fn smoke_cm_route_compose_and_depth() -> TestResult {
    // Stage-1 route composition: parent route + new hop = child route.
    // Host → port 3 = 0x03; depth-1 switch → port 5 = 0x0503;
    // depth-2 switch → port 1 = 0x010503.
    use crate::cm::{compose_downstream, route_depth};
    let r0 = 0u64;
    if route_depth(r0) != 0 {
        return TestResult::Fail("thunderbolt: host depth must be 0");
    }
    let r1 = match compose_downstream(r0, 0, 3) {
        Some(r) => r,
        None => return TestResult::Fail("thunderbolt: compose host->port3 failed"),
    };
    if r1 != 0x03 || route_depth(r1) != 1 {
        return TestResult::Fail("thunderbolt: depth-1 route wrong");
    }
    let r2 = match compose_downstream(r1, 1, 5) {
        Some(r) => r,
        None => return TestResult::Fail("thunderbolt: compose depth1->port5 failed"),
    };
    if r2 != 0x0503 || route_depth(r2) != 2 {
        return TestResult::Fail("thunderbolt: depth-2 route wrong");
    }
    let r3 = match compose_downstream(r2, 2, 1) {
        Some(r) => r,
        None => return TestResult::Fail("thunderbolt: compose depth2->port1 failed"),
    };
    if r3 != 0x01_0503 || route_depth(r3) != 3 {
        return TestResult::Fail("thunderbolt: depth-3 route wrong");
    }
    // Compose at a depth where the parent already has a non-zero hop
    // byte must reject — that would clobber the existing hop.
    if compose_downstream(r3, 0, 7).is_some() {
        return TestResult::Fail("thunderbolt: compose over existing hop not rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/thunderbolt/cm", smoke_cm_route_compose_and_depth);

fn smoke_adapter_type_decode_known_ids() -> TestResult {
    // Every value Linux exposes through `enum tb_port_type` must
    // decode back through `AdapterType::from_raw`. Unknown values
    // must return None — caller logs them but doesn't crash.
    use crate::adapter::AdapterType;
    let cases: &[(u32, AdapterType, &str)] = &[
        (0x000000, AdapterType::Inactive, "INACTIVE"),
        (0x000001, AdapterType::Port, "LANE"),
        (0x000002, AdapterType::Nhi, "NHI"),
        (0x0E0101, AdapterType::DpHdmiIn, "DP-IN"),
        (0x0E0102, AdapterType::DpHdmiOut, "DP-OUT"),
        (0x100101, AdapterType::PcieDown, "PCIe-DOWN"),
        (0x100102, AdapterType::PcieUp, "PCIe-UP"),
        (0x200101, AdapterType::Usb3Down, "USB3-DOWN"),
        (0x200102, AdapterType::Usb3Up, "USB3-UP"),
    ];
    for &(raw, ty, name) in cases {
        match AdapterType::from_raw(raw) {
            Some(t) if t == ty => {}
            _ => return TestResult::Fail("thunderbolt: adapter type decode miss"),
        }
        if AdapterType::from_raw(raw).unwrap().short_name() != name {
            return TestResult::Fail("thunderbolt: adapter short_name mismatch");
        }
    }
    // Unknown value (no protocol family at 0x3F0000) must decode to
    // None. The 24-bit mask must also strip stray high bits — pass
    // 0xFF00_0001 and expect `Port` (low 24 bits = 0x000001).
    if AdapterType::from_raw(0x3F_0000).is_some() {
        return TestResult::Fail("thunderbolt: unknown family decoded");
    }
    if AdapterType::from_raw(0xFF00_0001) != Some(AdapterType::Port) {
        return TestResult::Fail("thunderbolt: high bits not masked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/adapter",
    smoke_adapter_type_decode_known_ids
);

fn smoke_adapter_endpoint_predicates() -> TestResult {
    // PCIe / DP / USB3 endpoints all report `is_tunnel_endpoint`;
    // LANE and NHI do not. Catches a regression that adds a new
    // adapter variant without updating the matcher.
    use crate::adapter::AdapterType;
    if !AdapterType::PcieDown.is_tunnel_endpoint() {
        return TestResult::Fail("thunderbolt: PCIe-DOWN must be tunnel endpoint");
    }
    if !AdapterType::PcieUp.is_tunnel_endpoint() {
        return TestResult::Fail("thunderbolt: PCIe-UP must be tunnel endpoint");
    }
    if !AdapterType::DpHdmiIn.is_tunnel_endpoint() {
        return TestResult::Fail("thunderbolt: DP-IN must be tunnel endpoint");
    }
    if AdapterType::Port.is_tunnel_endpoint() {
        return TestResult::Fail("thunderbolt: LANE must not be tunnel endpoint");
    }
    if AdapterType::Nhi.is_tunnel_endpoint() {
        return TestResult::Fail("thunderbolt: NHI must not be tunnel endpoint");
    }
    if !AdapterType::PcieDown.is_pcie_source() {
        return TestResult::Fail("thunderbolt: PCIe-DOWN is the source");
    }
    if !AdapterType::PcieUp.is_pcie_sink() {
        return TestResult::Fail("thunderbolt: PCIe-UP is the sink");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/adapter",
    smoke_adapter_endpoint_predicates
);

fn smoke_topology_walk_synthetic_tree() -> TestResult {
    // Build a synthetic 3-switch tree in memory, hand it to
    // `walk_topology`, and confirm the walker visits every switch
    // in BFS order. Tree:
    //   host (route 0, depth 0): port 1 = LANE→switch A, port 2 =
    //     LANE→nothing, port 3 = NHI.
    //   switch A (route 0x01, depth 1): port 1 = LANE→upstream (host),
    //     port 2 = PCIe-DOWN, port 3 = DP-IN, port 4 = LANE→switch B.
    //   switch B (route 0x0401, depth 2): port 1 = LANE→upstream,
    //     port 2 = PCIe-UP, port 3 = DP-OUT.
    //
    // Stub probe returns canned switch / port headers from the tree.
    use crate::adapter::AdapterType;
    use crate::switch::{
        depth_matches_route, walk_topology, PortInfo, SwitchHeader, Topology, TopologyProbe,
        WalkError,
    };
    use alloc::vec::Vec;

    struct TreeProbe {
        // (route, vendor, device, upstream_port, max_port)
        switches: Vec<(u64, u16, u16, u8, u8)>,
        // (route, port, raw_type, has_peer)
        ports: Vec<(u64, u8, u32, bool)>,
    }
    impl TopologyProbe for TreeProbe {
        fn read_switch(&mut self, route: u64) -> Result<SwitchHeader, WalkError> {
            for &(r, v, d, up, mx) in &self.switches {
                if r == route {
                    return Ok(SwitchHeader {
                        vendor: v,
                        device: d,
                        upstream_port: up,
                        max_port: mx,
                    });
                }
            }
            Err(WalkError::ProbeFailed)
        }
        fn read_port(&mut self, route: u64, port: u8) -> Result<PortInfo, WalkError> {
            for &(r, p, raw, _) in &self.ports {
                if r == route && p == port {
                    return Ok(PortInfo { raw_type: raw });
                }
            }
            Err(WalkError::ProbeFailed)
        }
        fn port_has_peer(&mut self, route: u64, port: u8) -> Result<bool, WalkError> {
            for &(r, p, _, peer) in &self.ports {
                if r == route && p == port {
                    return Ok(peer);
                }
            }
            Ok(false)
        }
    }

    let mut probe = TreeProbe {
        switches: alloc::vec![
            (0x0000u64, 0x8086, 0x9A1B, 0, 3),
            (0x0001u64, 0x8086, 0x1234, 1, 4),
            (0x0401u64, 0x8086, 0x5678, 1, 3),
        ],
        ports: alloc::vec![
            // host port 1 = LANE, has switch A peer
            (0x0000u64, 1u8, AdapterType::Port as u32, true),
            // host port 2 = LANE, no peer
            (0x0000u64, 2u8, AdapterType::Port as u32, false),
            // host port 3 = NHI
            (0x0000u64, 3u8, AdapterType::Nhi as u32, false),
            // A port 1 = LANE upstream
            (0x0001u64, 1u8, AdapterType::Port as u32, true),
            // A port 2 = PCIe-DOWN (tunnel endpoint, no children)
            (0x0001u64, 2u8, AdapterType::PcieDown as u32, false),
            // A port 3 = DP-IN
            (0x0001u64, 3u8, AdapterType::DpHdmiIn as u32, false),
            // A port 4 = LANE, has B peer
            (0x0001u64, 4u8, AdapterType::Port as u32, true),
            // B port 1 = LANE upstream
            (0x0401u64, 1u8, AdapterType::Port as u32, true),
            // B port 2 = PCIe-UP
            (0x0401u64, 2u8, AdapterType::PcieUp as u32, false),
            // B port 3 = DP-OUT
            (0x0401u64, 3u8, AdapterType::DpHdmiOut as u32, false),
        ],
    };

    let mut topo = Topology::new(0);
    if walk_topology(&mut topo, &mut probe).is_err() {
        return TestResult::Fail("thunderbolt: walk_topology errored");
    }
    if topo.switch_count() != 3 {
        return TestResult::Fail("thunderbolt: switch count wrong");
    }
    // BFS order: host then A then B. (`pending` is a Vec used as a
    // stack — pushing children right-to-left is what BFS+stack
    // would do, but with a single descendant per parent here the
    // order is the same as BFS.)
    if topo.switches[0].route != 0 {
        return TestResult::Fail("thunderbolt: switch[0] must be host");
    }
    if topo.switches[1].route != 0x01 || topo.switches[1].depth != 1 {
        return TestResult::Fail("thunderbolt: switch[1] must be route 0x01 depth 1");
    }
    if topo.switches[2].route != 0x0401 || topo.switches[2].depth != 2 {
        return TestResult::Fail("thunderbolt: switch[2] must be route 0x0401 depth 2");
    }
    // depth-of-route must match recorded depth for every switch.
    for sw in &topo.switches {
        if !depth_matches_route(sw) {
            return TestResult::Fail("thunderbolt: depth/route mismatch");
        }
    }
    // host must NOT follow its NHI port: only LANE ports get
    // recursed.
    let host = &topo.switches[0];
    let host_nhi = host
        .adapters
        .iter()
        .find(|a| matches!(a.kind, Some(AdapterType::Nhi)));
    if host_nhi.is_none() {
        return TestResult::Fail("thunderbolt: host NHI adapter missing");
    }
    // switch A must have one PCIe-DOWN + one DP-IN endpoint.
    let a = &topo.switches[1];
    let endpoints: Vec<AdapterType> = a.tunnel_endpoints().filter_map(|x| x.kind).collect();
    if !endpoints.contains(&AdapterType::PcieDown) {
        return TestResult::Fail("thunderbolt: switch A missing PCIe-DOWN");
    }
    if !endpoints.contains(&AdapterType::DpHdmiIn) {
        return TestResult::Fail("thunderbolt: switch A missing DP-IN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/switch",
    smoke_topology_walk_synthetic_tree
);

fn smoke_topology_walk_skips_disconnected_lane() -> TestResult {
    // A LANE port with no peer must NOT be followed — the walker
    // would otherwise probe a nonexistent route and `ProbeFailed`
    // would tank the whole walk on a real device with empty USB-C
    // ports.
    use crate::adapter::AdapterType;
    use crate::switch::{
        walk_topology, PortInfo, SwitchHeader, Topology, TopologyProbe, WalkError,
    };
    use alloc::vec::Vec;

    struct EmptyProbe {
        attempts: u32,
    }
    impl TopologyProbe for EmptyProbe {
        fn read_switch(&mut self, route: u64) -> Result<SwitchHeader, WalkError> {
            self.attempts += 1;
            if route == 0 {
                Ok(SwitchHeader {
                    vendor: 0x8086,
                    device: 0xBEEF,
                    upstream_port: 0,
                    max_port: 2,
                })
            } else {
                Err(WalkError::ProbeFailed)
            }
        }
        fn read_port(&mut self, route: u64, port: u8) -> Result<PortInfo, WalkError> {
            // Two LANE adapters on the host (ports 1+2), no NHI port
            // in this scenario — every lane is unconnected.
            if route == 0 && (port == 1 || port == 2) {
                Ok(PortInfo {
                    raw_type: AdapterType::Port as u32,
                })
            } else {
                Err(WalkError::ProbeFailed)
            }
        }
        fn port_has_peer(&mut self, _route: u64, _port: u8) -> Result<bool, WalkError> {
            Ok(false) // every lane is empty
        }
    }

    let mut probe = EmptyProbe { attempts: 0 };
    let mut topo = Topology::new(0);
    if walk_topology(&mut topo, &mut probe).is_err() {
        return TestResult::Fail("thunderbolt: walk_topology errored on empty domain");
    }
    if topo.switch_count() != 1 {
        return TestResult::Fail("thunderbolt: empty domain must be host-only");
    }
    // read_switch must have been called exactly once — for route 0
    // (the host). Any extra calls mean the walker followed a disconnected
    // lane.
    let _ = Vec::<u8>::new(); // keep alloc imported (otherwise unused-import warns)
    if probe.attempts != 1 {
        return TestResult::Fail("thunderbolt: walker followed disconnected lane");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/thunderbolt/switch",
    smoke_topology_walk_skips_disconnected_lane
);

fn smoke_route_too_wide_rejected() -> TestResult {
    // The on-wire header is 22 bits high + 32 bits low = 54 bits;
    // anything wider must be rejected by the encoder. This is the
    // backstop for a future regression that widens the route past
    // what the switch header can carry.
    use crate::cm::{encode_cfg_read, Address, CfgSpace, CmError, Header};
    let hdr = Header {
        route: (1u64 << 54), // 1 bit too wide
        unknown: 0,
    };
    let addr = Address {
        offset: 0,
        length: 1,
        port: 0,
        space: CfgSpace::Switch,
        seq: 0,
    };
    let mut buf = [0u32; 3];
    match encode_cfg_read(hdr, addr, &mut buf) {
        Err(CmError::RouteTooWide) => TestResult::Pass,
        _ => TestResult::Fail("thunderbolt: 55-bit route not rejected"),
    }
}
kernel_test_in!("drivers/thunderbolt/cm", smoke_route_too_wide_rejected);
