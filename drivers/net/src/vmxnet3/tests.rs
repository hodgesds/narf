//! vmxnet3 smokes — Stage 0 (PCI match) + Stage 1 (DriverShared
//! sizing / DSAL+DSAH split) + Stage 2 (descriptor / queue-desc
//! layout assertions).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::vmxnet3::{self, regs, shared};

// ── Stage 0: PCI match table ────────────────────────────────────────

fn smoke_vmxnet3_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    vmxnet3::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m| {
        m.name == "vmxnet3"
            && matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: vmxnet3::VMWARE_VENDOR,
                    device: vmxnet3::VMWARE_DEV_VMXNET3,
                }
            )
    });
    if !matched {
        return TestResult::Fail("vmxnet3 PCI match table entry missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_pci_match_table);

// ── Stage 0: register offsets agree with VMware's vmxnet3_defs.h ────

fn smoke_vmxnet3_bar1_register_offsets() -> TestResult {
    // BAR1 (VD — control plane) offsets per vmxnet3_defs.h. A drift
    // here would point DSAL at the wrong slot and Activate would
    // either read garbage or rejected by the device.
    if regs::REG_VRRS != 0x00 {
        return TestResult::Fail("REG_VRRS offset drift");
    }
    if regs::REG_UVRS != 0x08 {
        return TestResult::Fail("REG_UVRS offset drift");
    }
    if regs::REG_DSAL != 0x10 {
        return TestResult::Fail("REG_DSAL offset drift");
    }
    if regs::REG_DSAH != 0x18 {
        return TestResult::Fail("REG_DSAH offset drift");
    }
    if regs::REG_CMD != 0x20 {
        return TestResult::Fail("REG_CMD offset drift");
    }
    if regs::REG_MACL != 0x28 {
        return TestResult::Fail("REG_MACL offset drift");
    }
    if regs::REG_MACH != 0x30 {
        return TestResult::Fail("REG_MACH offset drift");
    }
    if regs::REG_ICR != 0x38 {
        return TestResult::Fail("REG_ICR offset drift");
    }
    if regs::REG_ECR != 0x40 {
        return TestResult::Fail("REG_ECR offset drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_bar1_register_offsets);

fn smoke_vmxnet3_bar0_doorbell_offsets() -> TestResult {
    // BAR0 (PT — pass-through doorbells). Bit drift here would
    // cause the device to never see the producer cursor move and
    // the ring would sit idle.
    if regs::REG_IMR != 0x000 {
        return TestResult::Fail("REG_IMR offset drift");
    }
    if regs::REG_TXPROD != 0x600 {
        return TestResult::Fail("REG_TXPROD offset drift");
    }
    if regs::REG_RXPROD != 0x800 {
        return TestResult::Fail("REG_RXPROD offset drift");
    }
    if regs::REG_RXPROD2 != 0xA00 {
        return TestResult::Fail("REG_RXPROD2 offset drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_bar0_doorbell_offsets);

fn smoke_vmxnet3_cmd_codes() -> TestResult {
    // "set" class starts at 0xCAFE0000; "get" class at 0xF00D0000.
    // ACTIVATE_DEV must be exactly the first set-class code; the
    // device decodes the high bits as a class selector.
    if regs::VMXNET3_CMD_ACTIVATE_DEV != 0xCAFE_0000 {
        return TestResult::Fail("CMD_ACTIVATE_DEV value drift");
    }
    if regs::VMXNET3_CMD_GET_LINK != 0xF00D_0002 {
        return TestResult::Fail("CMD_GET_LINK value drift");
    }
    if regs::VMXNET3_CMD_RESET_DEV != 0xCAFE_0002 {
        return TestResult::Fail("CMD_RESET_DEV value drift");
    }
    if regs::VMXNET3_CMD_QUIESCE_DEV != 0xCAFE_0001 {
        return TestResult::Fail("CMD_QUIESCE_DEV value drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_cmd_codes);

fn smoke_vmxnet3_magic_matches_linux() -> TestResult {
    // VMXNET3_REV1_MAGIC = 3133079265 (= 0xBABEFEE1). A drift makes
    // every ACTIVATE_DEV fail because the device verifies magic
    // before consuming devRead.
    if regs::VMXNET3_REV1_MAGIC != 3_133_079_265 {
        return TestResult::Fail("VMXNET3_REV1_MAGIC drift");
    }
    if regs::VMXNET3_REV1_MAGIC != 0xBABE_FEE1 {
        return TestResult::Fail("magic should hex-print as 0xBABEFEE1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_magic_matches_linux);

// ── Stage 1: shared-struct sizing ───────────────────────────────────

fn smoke_vmxnet3_driver_info_layout() -> TestResult {
    // `Vmxnet3_DriverInfo` is exactly 16 bytes (4 × u32).
    if core::mem::size_of::<shared::Vmxnet3DriverInfo>() != 16 {
        return TestResult::Fail("DriverInfo size != 16");
    }
    // The GOS info pack-up must produce the bits the device expects.
    // gosType=1 (Linux), gosBits=0, gosVer=0, gosMisc=0 ⇒ bit 2 set.
    let g = shared::Vmxnet3GOSInfo {
        bits: 0,
        gos_type: 1,
        gos_ver: 0,
        gos_misc: 0,
    };
    if g.to_raw() != (1 << 2) {
        return TestResult::Fail("GOSInfo pack: gos_type=1 should land at bit 2");
    }
    // gosVer 0x42 ⇒ bits 6..21.
    let g2 = shared::Vmxnet3GOSInfo {
        bits: 0,
        gos_type: 0,
        gos_ver: 0x42,
        gos_misc: 0,
    };
    if g2.to_raw() != (0x42 << 6) {
        return TestResult::Fail("GOSInfo pack: gos_ver should land at bit 6");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_driver_info_layout);

fn smoke_vmxnet3_misc_conf_layout() -> TestResult {
    // `Vmxnet3_MiscConf` is exactly 72 bytes. The const_assert in
    // shared.rs already enforces this at compile time; the runtime
    // smoke verifies the value isn't paper-over-broken by a future
    // edit that loosens the assert.
    if core::mem::size_of::<shared::Vmxnet3MiscConf>() != 72 {
        return TestResult::Fail("MiscConf size != 72");
    }
    if core::mem::size_of::<shared::Vmxnet3IntrConf>() != 40 {
        return TestResult::Fail("IntrConf size != 40");
    }
    if core::mem::size_of::<shared::Vmxnet3RxFilterConf>() != 4 + 2 + 2 + 8 + 4 * 128 {
        return TestResult::Fail("RxFilterConf size off");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_misc_conf_layout);

fn smoke_vmxnet3_queue_desc_layout() -> TestResult {
    // Both queue descriptors must be 256 bytes — that's the magic
    // "128-byte aligned" the device assumes in `vmxnet3_defs.h`
    // (`u8 _pad[72]` brings each to a power-of-two multiple).
    if core::mem::size_of::<shared::Vmxnet3TxQueueDesc>() != 256 {
        return TestResult::Fail("TxQueueDesc size != 256");
    }
    if core::mem::size_of::<shared::Vmxnet3RxQueueDesc>() != 256 {
        return TestResult::Fail("RxQueueDesc size != 256");
    }
    if core::mem::size_of::<shared::Vmxnet3TxQueueConf>() != 64 {
        return TestResult::Fail("TxQueueConf size != 64");
    }
    if core::mem::size_of::<shared::Vmxnet3RxQueueConf>() != 64 {
        return TestResult::Fail("RxQueueConf size != 64");
    }
    if core::mem::size_of::<shared::UPT1TxStats>() != 80 {
        return TestResult::Fail("UPT1TxStats size != 80");
    }
    if core::mem::size_of::<shared::UPT1RxStats>() != 80 {
        return TestResult::Fail("UPT1RxStats size != 80");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_queue_desc_layout);

// ── Stage 2: descriptor packing ─────────────────────────────────────

fn smoke_vmxnet3_txdesc_round_trip() -> TestResult {
    // Single-buffer TX desc: addr=0xDEADBEEF_CAFEF00D, len=1500,
    // gen=1, EOP, CQ. Must round-trip with the right bit positions.
    let d = shared::Vmxnet3TxDesc::new(
        0xDEAD_BEEF_CAFE_F00Du64,
        1500,
        1,
        true,
        true,
    );
    if d.addr != 0xDEAD_BEEF_CAFE_F00Du64 {
        return TestResult::Fail("addr round-trip");
    }
    // dword2 = len:14 | gen<<14.
    if d.dword2 & regs::TXD_LEN_MASK != 1500 {
        return TestResult::Fail("len field");
    }
    if (d.dword2 >> regs::TXD_GEN_SHIFT) & 1 != 1 {
        return TestResult::Fail("gen bit position");
    }
    // dword3 has EOP at bit 12, CQ at bit 13.
    if d.dword3 & (1 << regs::TXD_EOP_SHIFT) == 0 {
        return TestResult::Fail("EOP not set");
    }
    if d.dword3 & (1 << regs::TXD_CQ_SHIFT) == 0 {
        return TestResult::Fail("CQ not set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_txdesc_round_trip);

fn smoke_vmxnet3_descriptor_sizes_are_16() -> TestResult {
    // Every descriptor type in vmxnet3 is exactly 16 bytes. A drift
    // would mis-stride every ring walk. Compile-time const_asserts
    // already enforce this; the smoke documents the contract.
    if core::mem::size_of::<shared::Vmxnet3TxDesc>() != 16 {
        return TestResult::Fail("TxDesc size != 16");
    }
    if core::mem::size_of::<shared::Vmxnet3RxDesc>() != 16 {
        return TestResult::Fail("RxDesc size != 16");
    }
    if core::mem::size_of::<shared::Vmxnet3TxCompDesc>() != 16 {
        return TestResult::Fail("TxCompDesc size != 16");
    }
    if core::mem::size_of::<shared::Vmxnet3RxCompDesc>() != 16 {
        return TestResult::Fail("RxCompDesc size != 16");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_descriptor_sizes_are_16);

fn smoke_vmxnet3_ring_sizing_fits_in_one_page() -> TestResult {
    // 256 × 16 = 4096 = one 4 KiB page. Stage-2 ring sizing keeps
    // every descriptor ring inside a single alloc_coherent call so
    // we never have to chase a multi-page DMA region.
    if regs::TX_RING_LEN * regs::TX_DESC_BYTES != 4096 {
        return TestResult::Fail("TX ring not 4 KiB");
    }
    if regs::RX_RING_LEN * regs::RX_DESC_BYTES != 4096 {
        return TestResult::Fail("RX ring not 4 KiB");
    }
    if regs::TX_COMP_RING_LEN * regs::TX_COMP_DESC_BYTES != 4096 {
        return TestResult::Fail("TX comp ring not 4 KiB");
    }
    if regs::RX_COMP_RING_LEN * regs::RX_COMP_DESC_BYTES != 4096 {
        return TestResult::Fail("RX comp ring not 4 KiB");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_ring_sizing_fits_in_one_page);

fn smoke_vmxnet3_dsa_split_round_trips_64_bit_phys() -> TestResult {
    // Stage-0 split: write low 32 bits to DSAL, high 32 to DSAH. A
    // careless cast (e.g. `phys as u32` on the high half) would
    // truncate to the low word and the device would either fail to
    // find the shared struct or DMA into the wrong page.
    let phys: u64 = 0xDEAD_BEEF_CAFE_F00Du64;
    let lo = (phys & 0xFFFF_FFFF) as u32;
    let hi = (phys >> 32) as u32;
    if lo != 0xCAFE_F00D {
        return TestResult::Fail("DSAL low half");
    }
    if hi != 0xDEAD_BEEF {
        return TestResult::Fail("DSAH high half");
    }
    // And: recombining low | high << 32 must round-trip identity.
    let recombined: u64 = (lo as u64) | ((hi as u64) << 32);
    if recombined != phys {
        return TestResult::Fail("DSAL/DSAH split lost bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/vmxnet3",
    smoke_vmxnet3_dsa_split_round_trips_64_bit_phys
);
