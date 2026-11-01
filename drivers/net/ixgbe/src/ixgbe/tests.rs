//! ixgbe driver smokes — co-located per project convention.
//!
//! Stage 1: PCI match table + register-decoder structural tests.
//! Stage 2: EEPROM word decode round-trip.
//! Stage 3: AdvTxDesc cmd_type_len bit packing.
//! Stage 4: RxDesc layout + size assertions.
//! Stage 5: live MSI-X enable (Skip when no silicon).
//! Stage 6: HwNic adapter surface.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    eeprom_decode, eerd_start, name_for, AdvTxDesc, RxDesc, ADVTXD_DCMD_DEXT, ADVTXD_DCMD_EOP,
    ADVTXD_DCMD_IFCS, ADVTXD_DCMD_RS, ADVTXD_DTYP_DATA, EERD_START, IXGBE_DEV_82599EB,
    IXGBE_DEV_X540, IXGBE_DEV_X550, IXGBE_DEV_X550EM_X, IXGBE_VENDOR,
};

/// In-memory register bank for fixtures: 64 KiB of BAR0 window,
/// covering every register this stream programs (highest is
/// MRQC at 0x0EC80). Lives here (not in queues.rs) because this
/// test module is x86_64-only while the driver builds for both
/// arches — a test-only helper in the driver module would trip
/// dead-code on aarch64.
struct FakeBank {
    regs: alloc::vec::Vec<u32>,
}

impl FakeBank {
    fn new() -> Self {
        Self {
            regs: alloc::vec![0u32; 0x10000 / 4],
        }
    }
}

impl super::queues::RegBank for FakeBank {
    fn read32(&self, offset: u64) -> u32 {
        if offset % 4 != 0 {
            return 0;
        }
        self.regs.get((offset / 4) as usize).copied().unwrap_or(0)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        if offset % 4 != 0 {
            return;
        }
        if let Some(slot) = self.regs.get_mut((offset / 4) as usize) {
            *slot = value;
        }
    }
}

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_ixgbe_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let want = [
        IXGBE_DEV_82599EB,
        IXGBE_DEV_X540,
        IXGBE_DEV_X550,
        IXGBE_DEV_X550EM_X,
    ];
    for did in want {
        let matched = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: IXGBE_VENDOR, device,
            } if device == did)
        });
        if !matched {
            return TestResult::Fail("ixgbe PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_pci_match_table);

fn smoke_ixgbe_name_for_known_ids() -> TestResult {
    if name_for(IXGBE_DEV_82599EB) != "ixgbe-82599eb" {
        return TestResult::Fail("82599eb name");
    }
    if name_for(IXGBE_DEV_X540) != "ixgbe-x540" {
        return TestResult::Fail("x540 name");
    }
    if name_for(IXGBE_DEV_X550) != "ixgbe-x550" {
        return TestResult::Fail("x550 name");
    }
    if name_for(IXGBE_DEV_X550EM_X) != "ixgbe-x550em" {
        return TestResult::Fail("x550em name");
    }
    if name_for(0xFFFF) != "ixgbe" {
        return TestResult::Fail("default name");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_name_for_known_ids);

// ── Stage 2: EEPROM decoder ────────────────────────────────────────

fn smoke_ixgbe_eeprom_decode_round_trip() -> TestResult {
    // Datasheet §10.2.4.2: result lives in [31:16].
    let raw = (0xBEEFu32 << 16) | EERD_START | (1 << 1);
    if eeprom_decode(raw) != 0xBEEF {
        return TestResult::Fail("eeprom_decode upper-half extraction wrong");
    }
    let start = eerd_start(0x0042);
    if start & EERD_START == 0 {
        return TestResult::Fail("eerd_start did not set START bit");
    }
    if start >> 2 != 0x0042 {
        return TestResult::Fail("eerd_start address did not land at bit 2");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_eeprom_decode_round_trip);

// ── Stage 3: TX descriptor packing ─────────────────────────────────

fn smoke_ixgbe_advtxd_ctrl_word() -> TestResult {
    let cw = AdvTxDesc::ctrl_word(0x40);
    let want_flags =
        ADVTXD_DTYP_DATA | ADVTXD_DCMD_DEXT | ADVTXD_DCMD_RS | ADVTXD_DCMD_IFCS | ADVTXD_DCMD_EOP;
    if cw & want_flags != want_flags {
        return TestResult::Fail("ctrl_word missing required bits");
    }
    if cw & 0xFFFF != 0x40 {
        return TestResult::Fail("ctrl_word length field wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_advtxd_ctrl_word);

fn smoke_ixgbe_advtxd_size_align() -> TestResult {
    if core::mem::size_of::<AdvTxDesc>() != 16 {
        return TestResult::Fail("AdvTxDesc not 16 bytes");
    }
    if core::mem::align_of::<AdvTxDesc>() != 16 {
        return TestResult::Fail("AdvTxDesc not 16-byte aligned");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_advtxd_size_align);

// ── Stage 4: RX descriptor layout ──────────────────────────────────

fn smoke_ixgbe_rxdesc_layout() -> TestResult {
    if core::mem::size_of::<RxDesc>() != 16 {
        return TestResult::Fail("RxDesc not 16 bytes");
    }
    if core::mem::align_of::<RxDesc>() != 16 {
        return TestResult::Fail("RxDesc not 16-byte aligned");
    }
    // Status byte at offset 12 (per datasheet §7.1.5 legacy).
    let d = RxDesc {
        addr: 0,
        length: 0,
        csum: 0,
        status: 0xAB,
        errors: 0,
        special: 0,
    };
    let p = (&d) as *const _ as *const u8;
    // SAFETY: structurally-sized read in-bounds.
    let off12 = unsafe { *p.add(12) };
    if off12 != 0xAB {
        return TestResult::Fail("RxDesc.status not at offset 12");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_rxdesc_layout);

// ── Stage 5: live MSI-X enable (skips off real silicon) ────────────

fn smoke_ixgbe_live_bring_up() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: the kernel-test runner executes post-boot, so the memory
    // map and allocator are online; `ECAM_DEFAULT_BASE` is the standard
    // MMCONFIG window and the enumerator only reads 4-byte config words,
    // rejecting all-1s for unpopulated slots.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == IXGBE_VENDOR
            && (d.id.device == IXGBE_DEV_82599EB
                || d.id.device == IXGBE_DEV_X540
                || d.id.device == IXGBE_DEV_X550
                || d.id.device == IXGBE_DEV_X550EM_X)
    });
    if !has {
        return TestResult::Skip("no ixgbe-class NIC");
    }
    __reset_for_test();
    super::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !super::is_probed() {
        return TestResult::Fail("ixgbe not probed");
    }
    let mac = super::with_controller(|c| c.mac).unwrap_or([0; 6]);
    if mac == [0; 6] || mac == [0xFF; 6] {
        return TestResult::Fail("MAC reads as all-zero or all-FF");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_live_bring_up);

// ── Stage 6: HwNic adapter surface ─────────────────────────────────

fn smoke_ixgbe_hwnic_surface() -> TestResult {
    // Compile-time only: assert that Ixgbe implements HwNic with the
    // expected NicModel. We can't actually instantiate without
    // silicon, so this is a type-gated check.
    use crate::{HwNic, NicModel};
    fn _accepts<T: HwNic>(_: &T) {}
    let _ = NicModel::IntelIxgbe.primary_pci_id();
    // Also assert the `model()` method returns IntelIxgbe — verified
    // via with_controller if the device is bound; otherwise just
    // assert the surface exists without crashing.
    if let Some(model) = super::with_controller(|c| c.model()) {
        if model != NicModel::IntelIxgbe {
            return TestResult::Fail("model() mismatch");
        }
    }
    let _ = _accepts::<super::Ixgbe>;
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_hwnic_surface);

// ── Multi-queue keystone: register addressing + IVAR routing ─────

fn smoke_ixgbe_queue_regs_match_legacy_q0() -> TestResult {
    use super::queues::{rx_queue_regs, tx_queue_regs};
    // Datasheet §8.2 queue-0 addresses (the old per-constant names
    // were deleted once the helpers became the single source).
    let rx = match rx_queue_regs(0) {
        Some(r) => r,
        None => return TestResult::Fail("rx_queue_regs(0) is None"),
    };
    if rx.rdbal != 0x01000
        || rx.rdbah != 0x01004
        || rx.rdlen != 0x01008
        || rx.rdh != 0x01010
        || rx.rdt != 0x01018
        || rx.rxdctl != 0x01028
        || rx.srrctl != 0x01014
    {
        return TestResult::Fail("rx queue-0 block disagrees with datasheet addresses");
    }
    let tx = match tx_queue_regs(0) {
        Some(t) => t,
        None => return TestResult::Fail("tx_queue_regs(0) is None"),
    };
    if tx.tdbal != 0x06000
        || tx.tdbah != 0x06004
        || tx.tdlen != 0x06008
        || tx.tdh != 0x06010
        || tx.tdt != 0x06018
        || tx.txdctl != 0x06028
    {
        return TestResult::Fail("tx queue-0 block disagrees with datasheet addresses");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_queue_regs_match_legacy_q0);

fn smoke_ixgbe_queue_regs_stride_and_banks() -> TestResult {
    use super::queues::{rx_queue_regs, tx_queue_regs};
    let rx0 = match rx_queue_regs(0) {
        Some(r) => r,
        None => return TestResult::Fail("rx_queue_regs(0) is None"),
    };
    let rx1 = match rx_queue_regs(1) {
        Some(r) => r,
        None => return TestResult::Fail("rx_queue_regs(1) is None"),
    };
    if rx1.rdbal != rx0.rdbal + 0x40 || rx1.rxdctl != rx0.rxdctl + 0x40 {
        return TestResult::Fail("rx stride is not 0x40");
    }
    if match rx_queue_regs(63) {
        Some(r) => r.rdbal,
        None => return TestResult::Fail("rx_queue_regs(63) is None"),
    } != 0x01000 + 63 * 0x40
    {
        return TestResult::Fail("rx queue 63 base wrong");
    }
    // Second RX bank: queues 64..127 live at 0x0D000 + 0x40*(q-64).
    if match rx_queue_regs(64) {
        Some(r) => r.rdbal,
        None => return TestResult::Fail("rx_queue_regs(64) is None"),
    } != 0x0D000
    {
        return TestResult::Fail("rx queue 64 second-bank base wrong");
    }
    if match rx_queue_regs(127) {
        Some(r) => r.rdbal,
        None => return TestResult::Fail("rx_queue_regs(127) is None"),
    } != 0x0D000 + 63 * 0x40
    {
        return TestResult::Fail("rx queue 127 base wrong");
    }
    if match tx_queue_regs(127) {
        Some(t) => t.tdbal,
        None => return TestResult::Fail("tx_queue_regs(127) is None"),
    } != 0x06000 + 127 * 0x40
    {
        return TestResult::Fail("tx queue 127 base wrong");
    }
    if rx_queue_regs(128).is_some() || tx_queue_regs(128).is_some() {
        return TestResult::Fail("queue 128 accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_queue_regs_stride_and_banks);

fn smoke_ixgbe_ivar_routing() -> TestResult {
    use super::queues::{
        ivar_field, ivar_reg, route_misc_vector, route_queue_vector, RegBank, REG_IVAR_BASE,
        REG_IVAR_MISC,
    };
    if ivar_reg(0) != Some(0x00900) || ivar_reg(1) != Some(0x00900) {
        return TestResult::Fail("IVAR[0] is not 0x00900");
    }
    if ivar_reg(2) != Some(0x00904) || ivar_reg(127) != Some(0x00900 + 4 * 63) {
        return TestResult::Fail("IVAR register index wrong");
    }
    if ivar_field(0, 0, false) != 0x80 || ivar_field(0, 0, true) != 0x8000 {
        return TestResult::Fail("IVAR queue-0 field packing wrong");
    }
    let mut bank = FakeBank::new();
    if !route_queue_vector(&mut bank, 0, 0) {
        return TestResult::Fail("route_queue_vector(0) failed");
    }
    if bank.read32(REG_IVAR_BASE) != 0x8080 {
        return TestResult::Fail("IVAR[0] queue-0 routing is not 0x8080");
    }
    if !route_queue_vector(&mut bank, 1, 3) {
        return TestResult::Fail("route_queue_vector(1) failed");
    }
    // Queue 1 (odd half) must not disturb queue 0's fields.
    if bank.read32(REG_IVAR_BASE) != 0x8383_8080 {
        return TestResult::Fail("IVAR[0] sibling queue clobbered");
    }
    // Re-routing queue 0 replaces only its own half.
    if !route_queue_vector(&mut bank, 0, 5) {
        return TestResult::Fail("route_queue_vector re-route failed");
    }
    if bank.read32(REG_IVAR_BASE) != 0x8383_8585 {
        return TestResult::Fail("IVAR[0] re-route clobbered sibling");
    }
    if route_misc_vector(&mut bank, 0) != 0x8000 || bank.read32(REG_IVAR_MISC) != 0x8000 {
        return TestResult::Fail("IVAR_MISC OTHER routing is not 0x8000");
    }
    if route_queue_vector(&mut bank, 128, 0) {
        return TestResult::Fail("route_queue_vector accepted queue 128");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_ivar_routing);

fn smoke_ixgbe_queue_config_validation() -> TestResult {
    use super::queues::{QueueConfig, QueueError};
    if QueueConfig::single().validate().is_err() {
        return TestResult::Fail("single-queue config rejected");
    }
    let zero = QueueConfig {
        num_tx: 0,
        num_rx: 1,
        ring_len: 32,
    };
    if zero.validate() != Err(QueueError::ZeroQueues) {
        return TestResult::Fail("zero TX queues accepted");
    }
    let many = QueueConfig {
        num_tx: 65,
        num_rx: 1,
        ring_len: 32,
    };
    if many.validate() != Err(QueueError::TooManyQueues) {
        return TestResult::Fail("65 queues accepted");
    }
    let small = QueueConfig {
        num_tx: 1,
        num_rx: 1,
        ring_len: 16,
    };
    if small.validate() != Err(QueueError::BadRingLen) {
        return TestResult::Fail("16-entry ring accepted");
    }
    let odd = QueueConfig {
        num_tx: 1,
        num_rx: 1,
        ring_len: 48,
    };
    if odd.validate() != Err(QueueError::BadRingLen) {
        return TestResult::Fail("non-power-of-two ring accepted");
    }
    let full = QueueConfig {
        num_tx: 64,
        num_rx: 64,
        ring_len: 64,
    };
    if full.validate().is_err() {
        return TestResult::Fail("64-queue config rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_queue_config_validation);

fn smoke_ixgbe_queue0_register_conversation() -> TestResult {
    use super::queues::{rx_queue_regs, tx_queue_regs, RegBank};
    use super::{RXDCTL_ENABLE, SRRCTL_BSIZE_2K, SRRCTL_DESCTYPE_LEGACY, TXDCTL_ENABLE};
    // Fake-bank replay of bring_up's queue-0 programming: base, length,
    // head/tail, SRRCTL, queue-enable — the exact register conversation
    // the hardware sees, minus DMA.
    let mut bank = FakeBank::new();
    let tx = match tx_queue_regs(0) {
        Some(t) => t,
        None => return TestResult::Fail("tx_queue_regs(0) is None"),
    };
    let rx = match rx_queue_regs(0) {
        Some(r) => r,
        None => return TestResult::Fail("rx_queue_regs(0) is None"),
    };
    let tx_phys: u64 = 0x1_0000_1000;
    let rx_phys: u64 = 0x1_0000_2000;
    bank.write32(tx.tdbal, tx_phys as u32);
    bank.write32(tx.tdbah, (tx_phys >> 32) as u32);
    bank.write32(tx.tdlen, 32 * 16);
    bank.write32(tx.tdh, 0);
    bank.write32(tx.tdt, 0);
    bank.set_bits(tx.txdctl, TXDCTL_ENABLE);
    bank.write32(rx.rdbal, rx_phys as u32);
    bank.write32(rx.rdbah, (rx_phys >> 32) as u32);
    bank.write32(rx.rdlen, 32 * 16);
    bank.write32(rx.rdh, 0);
    bank.write32(rx.rdt, 31);
    bank.write32(rx.srrctl, SRRCTL_BSIZE_2K | SRRCTL_DESCTYPE_LEGACY);
    bank.set_bits(rx.rxdctl, RXDCTL_ENABLE);
    if bank.read32(tx.tdbal) != tx_phys as u32
        || bank.read32(tx.tdbah) != (tx_phys >> 32) as u32
        || bank.read32(tx.tdlen) != 512
        || bank.read32(tx.txdctl) & TXDCTL_ENABLE == 0
    {
        return TestResult::Fail("TX queue-0 conversation wrong");
    }
    if bank.read32(rx.rdbal) != rx_phys as u32
        || bank.read32(rx.rdlen) != 512
        || bank.read32(rx.rdt) != 31
        || bank.read32(rx.srrctl) != (SRRCTL_BSIZE_2K | SRRCTL_DESCTYPE_LEGACY)
        || bank.read32(rx.rxdctl) & RXDCTL_ENABLE == 0
    {
        return TestResult::Fail("RX queue-0 conversation wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/ixgbe",
    smoke_ixgbe_queue0_register_conversation
);
