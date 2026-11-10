//! vmxnet3 smokes — Stage 0 (PCI match) + Stage 1 (DriverShared
//! sizing / DSAL+DSAH split) + Stage 2 (descriptor / queue-desc
//! layout assertions) + Stage 3 (datapath decode + generation rules
//! + publication, issue #800 vmxnet3 slice).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::Interface;

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
    let d = shared::Vmxnet3TxDesc::new(0xDEAD_BEEF_CAFE_F00Du64, 1500, 1, true, true);
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
kernel_test_in!(
    "drivers/net/vmxnet3",
    smoke_vmxnet3_ring_sizing_fits_in_one_page
);

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

// ── Stage 3: completion-descriptor decode ───────────────────────────
// All words below are built by hand from `vmxnet3_defs.h` bit
// positions — never from the implementation's constants — so a
// layout drift in the header fails the fixture, not the driver.

fn smoke_vmxnet3_tx_comp_decode() -> TestResult {
    // TxCompDesc per `vmxnet3_defs.h`: dword0 `txdIdx:12` at bits
    // [11:0]; dword3 `gen:1` at bit 31. A completion for EOP slot
    // 0x0AB with gen 1 must decode exactly that, and be "ready" for
    // the gen-1 pass only.
    let c = shared::Vmxnet3TxCompDesc {
        dword0: 0x0AB,
        ext2: 0,
        ext3: 0,
        dword3: 1 << 31,
    };
    if c.txd_idx() != 0x0AB {
        return TestResult::Fail("TxCompDesc txdIdx decode");
    }
    if c.gen() != 1 {
        return TestResult::Fail("TxCompDesc gen decode");
    }
    if !c.is_ready(1) {
        return TestResult::Fail("TxCompDesc ready for gen 1");
    }
    if c.is_ready(0) {
        return TestResult::Fail("TxCompDesc must not be ready for gen 0");
    }
    // A stale completion (gen 0) on the gen-1 pass is not ready.
    let stale = shared::Vmxnet3TxCompDesc {
        dword0: 0x005,
        ext2: 0,
        ext3: 0,
        dword3: 0,
    };
    if stale.is_ready(1) {
        return TestResult::Fail("stale TxCompDesc read as ready");
    }
    if stale.txd_idx() != 0x005 {
        return TestResult::Fail("stale TxCompDesc txdIdx decode");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_tx_comp_decode);

fn smoke_vmxnet3_rx_comp_decode() -> TestResult {
    // RxCompDesc per `vmxnet3_defs.h`: dword0 `rxdIdx:12` bits
    // [11:0], `eop:1` bit 14, `sop:1` bit 15; dword2 `len:14` bits
    // [13:0], `err:1` bit 14; dword3 `gen:1` bit 31. A single-buffer
    // 1500-byte frame in slot 0x123 must decode exactly that.
    let c = shared::Vmxnet3RxCompDesc {
        dword0: 0x123 | (1 << 14) | (1 << 15),
        rssHash: 0,
        dword2: 1500,
        dword3: 1 << 31,
    };
    if c.rxd_idx() != 0x123 {
        return TestResult::Fail("RxCompDesc rxdIdx decode");
    }
    if c.len() != 1500 {
        return TestResult::Fail("RxCompDesc len decode");
    }
    if !c.eop() || !c.sop() {
        return TestResult::Fail("RxCompDesc sop/eop decode");
    }
    if c.err() {
        return TestResult::Fail("RxCompDesc err must be clear");
    }
    if c.gen() != 1 {
        return TestResult::Fail("RxCompDesc gen decode");
    }
    if !c.is_ready(1) {
        return TestResult::Fail("RxCompDesc ready for gen 1");
    }
    // An EOP completion with err set is dropped by
    // `vmxnet3_rq_rx_complete` — the decode must surface it.
    let err = shared::Vmxnet3RxCompDesc {
        dword0: 0x123 | (1 << 14) | (1 << 15),
        rssHash: 0,
        dword2: 1500 | (1 << 14),
        dword3: 1 << 31,
    };
    if !err.err() {
        return TestResult::Fail("RxCompDesc err decode");
    }
    // A non-EOP completion (multi-buffer head) must not read as a
    // complete single-buffer frame.
    let head = shared::Vmxnet3RxCompDesc {
        dword0: 0x123 | (1 << 15),
        rssHash: 0,
        dword2: 1536,
        dword3: 1 << 31,
    };
    if head.eop() {
        return TestResult::Fail("head-only RxCompDesc must not claim eop");
    }
    if !head.sop() {
        return TestResult::Fail("head-only RxCompDesc must claim sop");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_rx_comp_decode);

fn smoke_vmxnet3_rx_desc_flags_pack() -> TestResult {
    // RxDesc `flags` per `vmxnet3_defs.h`: `len:14 | btype:1 |
    // dtype:1 | rsvd:15 | gen:1`. A 1536-byte HEAD buffer with gen 1
    // packs to `1536 | (1 << 31)`; a BODY buffer with gen 0 packs to
    // `1536 | (1 << 14)`.
    if shared::rx_desc_flags(1536, 0, 1) != 1536 | (1 << 31) {
        return TestResult::Fail("rx_desc_flags HEAD gen=1 pack");
    }
    if shared::rx_desc_flags(1536, 1, 0) != 1536 | (1 << 14) {
        return TestResult::Fail("rx_desc_flags BODY gen=0 pack");
    }
    // Length is 14 bits: 16384 truncates to 0, it must not spill
    // into the btype/gen bits.
    if shared::rx_desc_flags(16384, 0, 0) != 0 {
        return TestResult::Fail("rx_desc_flags len must mask to 14 bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_rx_desc_flags_pack);

// ── Stage 3: generation rules ───────────────────────────────────────
// The flip-on-wrap rule comes from the spec side: Linux
// `vmxnet3_cmd_ring_adv_next2fill` flips `ring->gen` when
// `next2fill` wraps, and QEMU `vmxnet3_ring_inc` XORs `ring->gen`
// on wrap. The whole datapath depends on it, so it is pinned here
// over a full 256-slot ring, not just at one boundary.

fn smoke_vmxnet3_ring_gen_flips_on_wrap() -> TestResult {
    if vmxnet3::flip_gen(1) != 0 || vmxnet3::flip_gen(0) != 1 {
        return TestResult::Fail("flip_gen must XOR the bit");
    }
    if vmxnet3::ring_advance(0, 256) != (1, false) {
        return TestResult::Fail("ring_advance mid-ring");
    }
    if vmxnet3::ring_advance(255, 256) != (0, true) {
        return TestResult::Fail("ring_advance must wrap at 255 with wrapped=true");
    }
    // Walk a full RX refill pass: start (next2fill=0, gen=0) — the
    // post-initial-fill state — and advance 256 slots. The gen must
    // flip exactly once, at the wrap, ending at (0, 1).
    let mut next2fill: u32 = 0;
    let mut gen: u32 = 0;
    let mut flips = 0;
    for _ in 0..256 {
        let (next, wrapped) = vmxnet3::ring_advance(next2fill, 256);
        next2fill = next;
        if wrapped {
            gen = vmxnet3::flip_gen(gen);
            flips += 1;
        }
    }
    if next2fill != 0 || gen != 1 || flips != 1 {
        return TestResult::Fail("refill pass must flip gen exactly once");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_ring_gen_flips_on_wrap);

fn smoke_vmxnet3_tx_gen_publish() -> TestResult {
    // The SOP publish protocol (`vmxnet3_drv.c::vmxnet3_map_pkt` +
    // `vmxnet3_tq_xmit`): the staged SOP desc carries the previous
    // gen (`gen ^ 1`, dword2 bit 14 per `vmxnet3_defs.h`
    // `VMXNET3_TXD_GEN_SHIFT`), and the final write flips that bit
    // in. For a 100-byte frame at gen 1, the staged dword2 is just
    // the length, and the published dword2 is length | (1 << 14).
    let staged = shared::Vmxnet3TxDesc::new(0x1000, 100, vmxnet3::tx_stage_gen(1), true, true);
    if staged.dword2 != 100 {
        return TestResult::Fail("staged TX desc must carry gen 0 (previous gen)");
    }
    if vmxnet3::tx_stage_gen(0) != 1 {
        return TestResult::Fail("tx_stage_gen must invert");
    }
    let published = staged.dword2 ^ (1 << 14);
    if published != 100 | (1 << 14) {
        return TestResult::Fail("published TX desc must carry gen 1");
    }
    // The built desc carries EOP + CQ in dword3 (bits 12/13 per
    // `vmxnet3_defs.h`), so the device writes a completion.
    if staged.dword3 & (1 << 12) == 0 || staged.dword3 & (1 << 13) == 0 {
        return TestResult::Fail("TX desc must request EOP + completion");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_tx_gen_publish);

// ── Stage 3: link decode ────────────────────────────────────────────
// Reply words shaped like the device's: QEMU reports
// `(1000 << 16) | 1` (1000 Mbit/s, link up —
// `vmxnet3.c: VMXNET3_LINK_SPEED | VMXNET3_LINK_STATUS_UP`).

fn smoke_vmxnet3_get_link_decode() -> TestResult {
    let up = vmxnet3::link_sample_from_get_link((1000 << 16) | 1);
    if !up.carrier {
        return TestResult::Fail("QEMU link word must decode carrier up");
    }
    if up.speed_mbps != Some(1000) {
        return TestResult::Fail("QEMU link word must decode 1000 Mbit/s");
    }
    let down = vmxnet3::link_sample_from_get_link(0);
    if down.carrier || down.speed_mbps.is_some() {
        return TestResult::Fail("zero link word must decode carrier down, no speed");
    }
    // Link up with a zero speed field: carrier, but no invented rate.
    let unknown = vmxnet3::link_sample_from_get_link(1);
    if !unknown.carrier || unknown.speed_mbps.is_some() {
        return TestResult::Fail("speed-0 link word must not invent a rate");
    }
    // 10 Gbit/s virtual link.
    let ten_g = vmxnet3::link_sample_from_get_link((10_000 << 16) | 1);
    if ten_g.speed_mbps != Some(10_000) {
        return TestResult::Fail("10G link word must decode 10000 Mbit/s");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_get_link_decode);

// ── Stage 3: publication ────────────────────────────────────────────
// Exercise two real QEMU devices with XTASK_QEMU_VMXNET3=1 and
// XTASK_QEMU_SECOND_NIC=1. A re-walk must preserve both controller handles.
fn smoke_vmxnet3_multi_instance() -> TestResult {
    use alloc::sync::Arc;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci};
    // SAFETY: q35 ECAM is mapped by the x86 test harness; init is idempotent.
    let _ = unsafe { narf_bus::init(narf_bus::x86_64::ECAM_DEFAULT_BASE) };
    let addresses: alloc::vec::Vec<_> = devices()
        .into_iter()
        .filter(|d| {
            d.id.vendor == vmxnet3::VMWARE_VENDOR && d.id.device == vmxnet3::VMWARE_DEV_VMXNET3
        })
        .map(|d| d.addr)
        .collect();
    if addresses.is_empty() {
        return TestResult::Skip("no vmxnet3 device present");
    }
    narf_bus::driver_match::__reset_for_test();
    vmxnet3::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() || vmxnet3::instance_count() != addresses.len() {
        return TestResult::Fail("not every vmxnet3 PCI function was probed");
    }
    let controllers: alloc::vec::Vec<_> = (0..addresses.len())
        .map(|i| vmxnet3::controller(i).unwrap())
        .collect();
    for (index, controller) in controllers.iter().enumerate() {
        if !addresses.contains(&controller.addr) || controller.ifname().is_empty() {
            return TestResult::Fail("vmxnet3 instance lost its address or interface name");
        }
        for other in &controllers[..index] {
            if Arc::ptr_eq(controller, other)
                || controller.addr == other.addr
                || controller.ifname() == other.ifname()
            {
                return TestResult::Fail("vmxnet3 PCI functions share controller state or a name");
            }
        }
        let iface = vmxnet3::Vmxnet3Iface(controller.clone());
        if !core::ptr::eq(iface.rx_ring(), &controller.rx_ipc_ring)
            || !core::ptr::eq(iface.tx_ring(), &controller.tx_ipc_ring)
        {
            return TestResult::Fail("vmxnet3 adapter resolved another device's rings");
        }
        let counts: alloc::vec::Vec<_> = controllers.iter().map(|c| c.stats().tx_ok).collect();
        let mut frame = [0u8; 64];
        frame[..6].fill(0xff);
        frame[6..12].copy_from_slice(&controller.mac);
        frame[12..14].copy_from_slice(&[0x88, 0xb5]);
        if narf_net::iface::send_on(controller.ifname(), &frame).is_err() {
            return TestResult::Fail("vmxnet3 instance TX failed");
        }
        for (peer, before) in counts.into_iter().enumerate() {
            if controllers[peer].stats().tx_ok != before + u64::from(peer == index) {
                return TestResult::Fail("vmxnet3 TX callback reached the wrong PCI function");
            }
        }
    }
    let _ = probe_all_pci(&authority);
    for (index, before) in controllers.iter().enumerate() {
        if !vmxnet3::controller(index).is_some_and(|after| Arc::ptr_eq(before, &after)) {
            return TestResult::Fail("vmxnet3 reprobe replaced a live controller");
        }
    }
    if vmxnet3::instance_count() != controllers.len() {
        return TestResult::Fail("vmxnet3 reprobe duplicated an interface");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_multi_instance);

// Gated on the device being present: under QEMU with
// `XTASK_QEMU_VMXNET3=1` this runs live; everywhere else it skips.

fn smoke_vmxnet3_published_iface() -> TestResult {
    if !vmxnet3::is_probed() {
        return TestResult::Skip("no vmxnet3 device present");
    }
    let iface = vmxnet3::Vmxnet3Iface(vmxnet3::probed_controller().unwrap());
    if iface.name().is_empty() {
        return TestResult::Fail("published iface has no name");
    }
    if iface.mac() == [0; 6] {
        return TestResult::Fail("published iface has zero MAC");
    }
    if iface.mtu() != 1500 {
        return TestResult::Fail("published iface MTU != 1500");
    }
    // `Interface::link_up` must agree with the controller's live
    // sample — the probe-time snapshot is not the source of truth.
    let live = vmxnet3::with_controller(|c| c.link_sample().carrier).unwrap_or(false);
    if iface.link_up() != live {
        return TestResult::Fail("Interface::link_up disagrees with live sample");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/vmxnet3", smoke_vmxnet3_published_iface);

// ── Completion sampling order ───────────────────────────────────────

/// Run `sample` against a slot holding `old` that the device overwrites
/// with the WHOLE of `new` after each possible number of host loads.
/// `sample(dword)` returns the sampled dwords when it reports the entry
/// ready. Whatever the interleaving, a ready sample must be `new` in
/// full; a slot that is not ready must not be read past its gen dword.
fn comp_sample_never_mixes(
    old: [u32; 4],
    new: [u32; 4],
    sample: impl Fn(&mut dyn FnMut(usize) -> u32) -> Option<[u32; 4]>,
) -> Result<(), &'static str> {
    for post_after in 0..=4usize {
        let slot = core::cell::Cell::new(old);
        let loads = core::cell::Cell::new(0usize);
        let sampled = sample(&mut |dword| {
            if loads.get() == post_after {
                slot.set(new);
            }
            loads.set(loads.get() + 1);
            slot.get()[dword]
        });
        let Some(got) = sampled else {
            // Not written yet: the driver polls again.
            if post_after == 0 {
                return Err("a completion posted before the sample read as stale");
            }
            if loads.get() != 1 {
                return Err("an unwritten slot was read past its gen dword");
            }
            continue;
        };
        if loads.get() != 4 {
            return Err("a ready sample is not exactly four dword loads");
        }
        if got != new {
            return Err("current gen sampled with the previous occupant's fields");
        }
    }
    Ok(())
}

fn smoke_vmxnet3_tx_comp_sample_never_mixes_occupants() -> TestResult {
    // A slot of a wrapped TX completion ring still holds the previous
    // pass's completion (other gen, older `txdIdx`) when the device
    // posts the next one. With the old `txdIdx` under the current gen
    // the driver credits the wrong TX slot.
    let old = [0x005, 0x1111_1111, 0x2222_2222, 0]; // gen 0
    let new = [0x0AB, 0x3333_3333, 0x4444_4444, 1 << 31]; // gen 1
    match comp_sample_never_mixes(old, new, |dword| {
        shared::Vmxnet3TxCompDesc::sample(1, dword).map(|c| [c.dword0, c.ext2, c.ext3, c.dword3])
    }) {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/net/vmxnet3",
    smoke_vmxnet3_tx_comp_sample_never_mixes_occupants
);

fn smoke_vmxnet3_rx_comp_sample_never_mixes_occupants() -> TestResult {
    // Same for the RX completion ring: the previous pass's `rxdIdx` and
    // `len` under the current gen deliver the wrong buffer or length.
    let old = [0x005 | (3 << 14), 0x1111_1111, 60, 0]; // gen 0
    let new = [0x0AB | (3 << 14), 0x3333_3333, 1514, 1 << 31]; // gen 1
    match comp_sample_never_mixes(old, new, |dword| {
        shared::Vmxnet3RxCompDesc::sample(1, dword)
            .map(|c| [c.dword0, c.rssHash, c.dword2, c.dword3])
    }) {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/net/vmxnet3",
    smoke_vmxnet3_rx_comp_sample_never_mixes_occupants
);
