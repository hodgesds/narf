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
    eeprom_decode, eerd_start, name_for, parse_tso_headers, tx_plan, AdvTxCtxtDesc, AdvTxDesc,
    RxDesc, ADVTXD_DCMD_DEXT, ADVTXD_DCMD_EOP, ADVTXD_DCMD_IFCS, ADVTXD_DCMD_RS, ADVTXD_DCMD_TSE,
    ADVTXD_DCMD_VLE, ADVTXD_DTYP_CTXT, ADVTXD_DTYP_DATA, ADVTXD_PAYLEN_SHIFT, ADVTXD_POPTS_IXSM,
    ADVTXD_POPTS_TXSM, ADVTXD_TUCMD_IPV4, ADVTXD_TUCMD_L4T_TCP, EERD_START, IXGBE_DEV_82599EB,
    IXGBE_DEV_X540, IXGBE_DEV_X550, IXGBE_DEV_X550EM_X, IXGBE_VENDOR,
};

/// In-memory register bank for fixtures: 0x14000 bytes of BAR0
/// window, covering every register this stream programs (highest is
/// PFMBMEM for VF 62 at 0x13F80 + 16 words = 0x13FC0; the canonical
/// 0x05xxx RSS block is covered too). Lives here (not in queues.rs)
/// because this test module is x86_64-only while the driver builds
/// for both arches — a test-only helper in the driver module would
/// trip dead-code on aarch64.
struct FakeBank {
    regs: alloc::vec::Vec<u32>,
}

impl FakeBank {
    fn new() -> Self {
        Self {
            regs: alloc::vec![0u32; 0x14000 / 4],
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

// ── RSS fixtures (commit 2) — append to tests.rs ────────────────

fn smoke_ixgbe_rss_packing() -> TestResult {
    use super::rss::{mrqc_word, reta_words, rssrk_words, IxgbeRss, RETA_ENTRIES};
    use narf_net::rss::RSS_KEY;
    if mrqc_word() != 0x00F3_0001 {
        return TestResult::Fail("MRQC word is not RSS-only + all hash fields");
    }
    let mut key = [0u8; 40];
    key.copy_from_slice(&RSS_KEY);
    let words = rssrk_words(&key);
    if words[0] != 0xda56_5a6d || words[9] != 0xfa01_acbe {
        return TestResult::Fail("RSSRK key packing wrong");
    }
    let rss = match IxgbeRss::standard(4) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("IxgbeRss::standard(4) failed"),
    };
    let reta = reta_words(&rss.table);
    // Balanced 4-queue table: entries 0..3 = 0,1,2,3.
    if reta[0] != 0x0302_0100 || reta[31] != 0x0302_0100 {
        return TestResult::Fail("RETA packing wrong");
    }
    if IxgbeRss::standard(0).is_ok() || IxgbeRss::standard(17).is_ok() {
        return TestResult::Fail("RSS queue-count validation failed");
    }
    let rss16 = match IxgbeRss::standard(16) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("IxgbeRss::standard(16) failed"),
    };
    for q in 0..16 {
        if rss16.table.iter().filter(|&&e| e as usize == q).count() != RETA_ENTRIES / 16 {
            return TestResult::Fail("RSS 16-queue table unbalanced");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_rss_packing);

fn smoke_ixgbe_rss_register_conversation() -> TestResult {
    use super::queues::RegBank;
    use super::rss::{IxgbeRss, REG_MRQC, REG_RETA_BASE, REG_RSSRK_BASE};
    let rss = match IxgbeRss::standard(4) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("IxgbeRss::standard(4) failed"),
    };
    let mut bank = FakeBank::new();
    rss.apply(&mut bank);
    if bank.read32(REG_MRQC) != 0x00F3_0001 {
        return TestResult::Fail("MRQC not programmed");
    }
    if bank.read32(REG_RSSRK_BASE) != 0xda56_5a6d {
        return TestResult::Fail("RSSRK[0] not programmed");
    }
    if bank.read32(REG_RETA_BASE) != 0x0302_0100 {
        return TestResult::Fail("RETA[0] not programmed");
    }
    // Hardware steering agrees with the shared stack-side hash.
    let mut frame = alloc::vec![0u8; 54];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14] = 0x45;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&[66, 9, 149, 187]);
    frame[30..34].copy_from_slice(&[161, 142, 100, 80]);
    frame[34..36].copy_from_slice(&2794u16.to_be_bytes());
    frame[36..38].copy_from_slice(&1766u16.to_be_bytes());
    let net_cfg = narf_net::rss::RssConfig::standard(4, 128);
    if rss.rx_queue(&frame) != net_cfg.rx_queue(&frame) {
        return TestResult::Fail("ixgbe RSS queue disagrees with net rss");
    }
    let mut arp = frame.clone();
    arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    if rss.rx_queue(&arp) != 0 {
        return TestResult::Fail("non-IP frame did not hash to queue 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_rss_register_conversation);

/// #1397 fixture: the RSS/VMDq register-map authority pins the
/// datasheet dual-map, and the RSS programming path writes the
/// canonical (Linux/compat) addresses — not a second literal.
/// The datasheet (rev. 2.6, 322429-007) dual-maps all three
/// registers: MRQC §8.2.3.7.12 (0x0EC80 / 0x05818), RSSRK
/// §8.2.3.7.14 (0x0EB80 / 0x05C80), RETA §8.2.3.7.15 (0x0EB00 /
/// 0x05C00), each "also mapped ... to maintain compatibility
/// with the 82598". The VMDq path (PR #1398) programs the 0x05
/// block; if this path ever redefined its own addresses, the
/// two would silently program different aliases of the same
/// registers again — this test fails first.
fn smoke_ixgbe_rss_reg_alias_map() -> TestResult {
    use super::queues::RegBank;
    use super::regs::{
        MRQE_VMDQ_32_RSS, MRQE_VMDQ_64_NO_RSS, MRQE_VMDQ_64_RSS, REG_MRQC, REG_MRQC_NATIVE,
        REG_RETA_BASE, REG_RETA_BASE_NATIVE, REG_RSSRK_BASE, REG_RSSRK_BASE_NATIVE, REG_STRIDE,
        RETA_REGS, RSSRK_REGS,
    };
    use super::rss::IxgbeRss;
    // 1. Shared authority == Linux's shipping map (ixgbe_type.h
    // :376/:417/:419) — the addresses the VMDq path programs.
    if REG_MRQC != 0x05818 || REG_RETA_BASE != 0x05C00 || REG_RSSRK_BASE != 0x05C80 {
        return TestResult::Fail("regs authority != Linux MRQC/RETA/RSSRK map");
    }
    // 2. Datasheet alias pairs (§8.2.3.7.12/.14/.15).
    if REG_MRQC_NATIVE != 0x0EC80
        || REG_RETA_BASE_NATIVE != 0x0EB00
        || REG_RSSRK_BASE_NATIVE != 0x0EB80
    {
        return TestResult::Fail("regs native aliases != datasheet 0x0E block");
    }
    // 3. Alias ranges end where the datasheet says: RETA
    // 0x05C00-0x05C7C, RSSRK 0x05C80-0x05CA4.
    if REG_STRIDE != 4
        || REG_RETA_BASE + REG_STRIDE * (RETA_REGS as u64 - 1) != 0x05C7C
        || REG_RSSRK_BASE + REG_STRIDE * (RSSRK_REGS as u64 - 1) != 0x05CA4
    {
        return TestResult::Fail("regs alias ranges != datasheet ends");
    }
    // 4. MRQE virtualization modes (§8.2.3.7.12; Linux :2332-:2334).
    if MRQE_VMDQ_64_NO_RSS != 0x8 || MRQE_VMDQ_32_RSS != 0xA || MRQE_VMDQ_64_RSS != 0xB {
        return TestResult::Fail("regs MRQE VMDq modes wrong");
    }
    // 5. The programming path writes the CANONICAL addresses:
    // read the fake bank back at literals, not via the REG_*
    // imports, so a reintroduced local literal fails here. The
    // native aliases must stay unwritten by apply().
    let rss = match IxgbeRss::standard(4) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("IxgbeRss::standard(4) failed"),
    };
    let mut bank = FakeBank::new();
    rss.apply(&mut bank);
    if bank.read32(0x05818) != 0x00F3_0001 {
        return TestResult::Fail("apply() did not program canonical MRQC");
    }
    if bank.read32(0x05C80) != 0xda56_5a6d {
        return TestResult::Fail("apply() did not program canonical RSSRK[0]");
    }
    if bank.read32(0x05C00) != 0x0302_0100 {
        return TestResult::Fail("apply() did not program canonical RETA[0]");
    }
    if bank.read32(0x0EC80) != 0 || bank.read32(0x0EB80) != 0 || bank.read32(0x0EB00) != 0 {
        return TestResult::Fail("apply() wrote a native alias address");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_rss_reg_alias_map);

// ── VLAN fixtures (commit 3) ─────────────────────────────────────

fn smoke_ixgbe_vlan_filter() -> TestResult {
    use super::queues::RegBank;
    use super::vlan::{
        vfta_slot, vfta_words, vlnctrl_word, VlanFilter, REG_VFTA_BASE, REG_VLNCTRL,
    };
    if vfta_slot(0) != (0, 1) || vfta_slot(32) != (1, 1) || vfta_slot(4095) != (127, 0x8000_0000) {
        return TestResult::Fail("VFTA slot mapping wrong");
    }
    if vfta_slot(100) != (3, 1 << 4) {
        return TestResult::Fail("VFTA slot for VID 100 wrong");
    }
    let words = vfta_words(&[0, 1, 100, 4095, 5000]);
    if words[0] != 0x3 || words[3] != (1 << 4) || words[127] != 0x8000_0000 {
        return TestResult::Fail("VFTA words wrong (5000 must be ignored)");
    }
    if vlnctrl_word(None) != 0x4000_8100 {
        return TestResult::Fail("VLNCTRL word without CFI wrong");
    }
    if vlnctrl_word(Some(false)) != 0x6000_8100 || vlnctrl_word(Some(true)) != 0x7000_8100 {
        return TestResult::Fail("VLNCTRL CFI words wrong");
    }
    let mut bank = FakeBank::new();
    let filter = VlanFilter {
        vids: alloc::vec![100, 200],
        cfi_match: None,
    };
    filter.apply(&mut bank);
    if bank.read32(REG_VFTA_BASE + 4 * 3) != (1 << 4) {
        return TestResult::Fail("VFTA VID 100 not programmed");
    }
    if bank.read32(REG_VFTA_BASE + 4 * 6) != (1 << 8) {
        return TestResult::Fail("VFTA VID 200 not programmed");
    }
    if bank.read32(REG_VLNCTRL) != 0x4000_8100 {
        return TestResult::Fail("VLNCTRL not programmed");
    }
    VlanFilter::clear(&mut bank);
    if bank.read32(REG_VFTA_BASE + 4 * 3) != 0 || bank.read32(REG_VLNCTRL) != 0x8100 {
        return TestResult::Fail("VLAN clear did not restore defaults");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vlan_filter);

// ── WoL fixtures (commit 4) ──────────────────────────────────────

fn smoke_ixgbe_wol() -> TestResult {
    use super::queues::RegBank;
    use super::wol::{
        program_ipv4, program_ipv6, wol_supported, WakeStatus, WolConfig, REG_WUC, REG_WUFC,
        REG_WUS, WUC_PME_EN,
    };
    if WolConfig::magic_only().wufc_word() != 0x2 {
        return TestResult::Fail("magic-only WUFC word wrong");
    }
    let all = WolConfig {
        link_change: true,
        magic: true,
        exact: true,
        multicast: true,
        broadcast: true,
        arp: true,
        ipv4: true,
        ipv6: true,
    };
    if all.wufc_word() != 0xFF {
        return TestResult::Fail("all-filters WUFC word wrong");
    }
    if !wol_supported(super::IXGBE_DEV_82599EB) {
        return TestResult::Fail("82599EB WoL must be supported");
    }
    if wol_supported(super::IXGBE_DEV_X540)
        || wol_supported(super::IXGBE_DEV_X550)
        || wol_supported(super::IXGBE_DEV_X550EM_X)
    {
        return TestResult::Fail("ungrounded/LOM-gated part claims WoL support");
    }
    let mut bank = FakeBank::new();
    WolConfig::magic_only().arm(&mut bank);
    if bank.read32(REG_WUS) != 0xFFFF_FFFF {
        return TestResult::Fail("WUS not cleared on arm");
    }
    if bank.read32(REG_WUFC) != 0x2 {
        return TestResult::Fail("WUFC not programmed on arm");
    }
    if bank.read32(REG_WUC) & WUC_PME_EN == 0 {
        return TestResult::Fail("WUC PME_En not set on arm");
    }
    WolConfig::disarm(&mut bank);
    if bank.read32(REG_WUFC) != 0 || bank.read32(REG_WUC) & WUC_PME_EN != 0 {
        return TestResult::Fail("disarm did not clear WUFC/PME_En");
    }
    let st = WakeStatus { raw: 0x1FF };
    if !st.link_change() || !st.magic() || !st.ipv6() || !st.manageability() {
        return TestResult::Fail("WakeStatus decode wrong");
    }
    if !program_ipv4(&mut bank, 0, [192, 168, 0, 1]) {
        return TestResult::Fail("program_ipv4 slot 0 failed");
    }
    if bank.read32(0x05840) != 0x0100_A8C0 {
        return TestResult::Fail("IP4AT word wrong");
    }
    if program_ipv4(&mut bank, 4, [10, 0, 0, 1]) {
        return TestResult::Fail("program_ipv4 accepted slot 4");
    }
    let mut v6 = [0u8; 16];
    for (i, b) in v6.iter_mut().enumerate() {
        *b = i as u8;
    }
    program_ipv6(&mut bank, v6);
    if bank.read32(0x05880) != 0x0302_0100 {
        return TestResult::Fail("IP6AT word 0 wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_wol);

// ── WoL board-cap gate (#1266) ────────────────────────────────────

fn smoke_ixgbe_wol_board_cap() -> TestResult {
    use super::queues::RegBank;
    use super::wol::{
        is_x540_or_newer, wol_allowed, WolBoardCap, WolConfig, REG_WUC, REG_WUFC, WOL_CAP_MASK,
        WOL_CAP_PORT0, WOL_CAP_PORT0_1, WUC_PME_EN,
    };
    // Cap constants are Linux's (ixgbe_type.h:2179-2181).
    if WOL_CAP_MASK != 0xC || WOL_CAP_PORT0_1 != 0x4 || WOL_CAP_PORT0 != 0x8 {
        return TestResult::Fail("WoL cap constants drifted from Linux");
    }
    // Rule table: (cap_bits, func) -> allows. Linux-literal
    // (ixgbe_main.c ixgbe_wol_supported, X540+ arm): masked 0x4
    // permits any func, masked 0x8 permits func 0 only, anything
    // else — including 0xC, both bits set — permits nothing.
    let cases: [(u16, u8, bool); 8] = [
        (0x0, 0, false),
        (0x0, 1, false),
        (0x4, 0, true),
        (0x4, 1, true),
        (0x8, 0, true),
        (0x8, 1, false),
        (0xC, 0, false),
        (0x14, 1, true), // masks to 0x4
    ];
    for (bits, func, want) in cases {
        let cap = WolBoardCap {
            cap_bits: bits,
            func,
        };
        if cap.allows() != want {
            return TestResult::Fail("WolBoardCap rule table mismatch");
        }
    }
    if WolBoardCap::default().allows() {
        return TestResult::Fail("default board record must permit nothing");
    }
    // Generation split: X540/X550/X550EM_x are X540-or-newer;
    // 82599EB is not, and unknown parts are neither.
    if !is_x540_or_newer(super::IXGBE_DEV_X540)
        || !is_x540_or_newer(super::IXGBE_DEV_X550)
        || !is_x540_or_newer(super::IXGBE_DEV_X550EM_X)
        || is_x540_or_newer(super::IXGBE_DEV_82599EB)
        || is_x540_or_newer(0xFFFF)
    {
        return TestResult::Fail("is_x540_or_newer split wrong");
    }
    // Gate predicate: 82599EB stands on its datasheet rule whatever
    // the record says; X540+ needs a permitting record; unknown
    // parts never pass, even with a permitting record.
    let none = WolBoardCap::default();
    let both = WolBoardCap {
        cap_bits: 0x4,
        func: 1,
    };
    let port0_f1 = WolBoardCap {
        cap_bits: 0x8,
        func: 1,
    };
    let port0_f0 = WolBoardCap {
        cap_bits: 0x8,
        func: 0,
    };
    if !wol_allowed(super::IXGBE_DEV_82599EB, none)
        || !wol_allowed(super::IXGBE_DEV_82599EB, both)
        || wol_allowed(super::IXGBE_DEV_X540, none)
        || !wol_allowed(super::IXGBE_DEV_X540, both)
        || wol_allowed(super::IXGBE_DEV_X550, port0_f1)
        || !wol_allowed(super::IXGBE_DEV_X550EM_X, port0_f0)
        || wol_allowed(0xFFFF, both)
    {
        return TestResult::Fail("wol_allowed gate wrong");
    }
    // Shared wake block: the X540 arm conversation is the same
    // WUFC/WUC programming Linux issues on its shared shutdown
    // path — no part-specific wake registers exist.
    let mut bank = FakeBank::new();
    WolConfig::magic_only().arm(&mut bank);
    if bank.read32(REG_WUFC) != 0x2 || bank.read32(REG_WUC) & WUC_PME_EN == 0 {
        return TestResult::Fail("X540 arm conversation differs from 82599");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_wol_board_cap);

// ── PM fixtures (commit 5) ───────────────────────────────────────

fn smoke_ixgbe_pm_plans() -> TestResult {
    use super::pm::{detach_plan, resume_rebuild_plan, suspend_plan};
    use super::queues::{rx_queue_regs, tx_queue_regs, QueueConfig, RegBank};
    use super::wol::WolConfig;
    use super::{RXDCTL_ENABLE, TXDCTL_ENABLE};
    let tx = match tx_queue_regs(0) {
        Some(t) => t,
        None => return TestResult::Fail("tx_queue_regs(0) is None"),
    };
    let rx = match rx_queue_regs(0) {
        Some(r) => r,
        None => return TestResult::Fail("rx_queue_regs(0) is None"),
    };
    let mut bank = FakeBank::new();
    bank.set_bits(tx.txdctl, TXDCTL_ENABLE);
    bank.set_bits(rx.rxdctl, RXDCTL_ENABLE);
    bank.set_bits(0x03000, 1);
    bank.set_bits(0x00018, 1 << 28);
    suspend_plan(&mut bank, None);
    if bank.read32(0x00888) != 0xFFFF_FFFF {
        return TestResult::Fail("suspend did not mask interrupts");
    }
    if bank.read32(0x03000) & 1 != 0 {
        return TestResult::Fail("suspend did not clear RXEN");
    }
    if bank.read32(tx.txdctl) & TXDCTL_ENABLE != 0 || bank.read32(rx.rxdctl) & RXDCTL_ENABLE != 0 {
        return TestResult::Fail("suspend did not disable queues");
    }
    if bank.read32(0x05808) != 0 {
        return TestResult::Fail("suspend without WoL left filters armed");
    }
    if resume_rebuild_plan(&mut bank, &QueueConfig::single(), &[0x1000], &[0x2000]).is_err() {
        return TestResult::Fail("resume rebuild failed on the 1/1 config");
    }
    if bank.read32(tx.txdctl) & TXDCTL_ENABLE == 0
        || bank.read32(rx.rxdctl) & RXDCTL_ENABLE == 0
        || bank.read32(0x03000) & 1 == 0
        || bank.read32(0x00880) != 1
    {
        return TestResult::Fail("resume did not re-enable datapath");
    }
    // Suspend with WoL, then detach extras.
    suspend_plan(&mut bank, Some(WolConfig::magic_only()));
    if bank.read32(0x05808) != 0x2 || bank.read32(0x05800) & (1 << 1) == 0 {
        return TestResult::Fail("suspend with WoL did not arm");
    }
    detach_plan(&mut bank);
    if bank.read32(0x00018) & (1 << 28) != 0 {
        return TestResult::Fail("detach did not clear DRV_LOAD");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_pm_plans);

// ── Resume-rebuild fixtures (§13l) ───────────────────────────────

fn smoke_ixgbe_pm_resume_rebuild() -> TestResult {
    use super::pm::resume_rebuild_plan;
    use super::queues::{rx_queue_regs, tx_queue_regs, QueueConfig, RegBank};
    use super::{FCTRL_BAM, FCTRL_MPE, FCTRL_UPE, RXDCTL_ENABLE, SRRCTL_BSIZE_2K, TXDCTL_ENABLE};
    let tx0 = match tx_queue_regs(0) {
        Some(t) => t,
        None => return TestResult::Fail("tx_queue_regs(0) is None"),
    };
    let rx0 = match rx_queue_regs(0) {
        Some(r) => r,
        None => return TestResult::Fail("rx_queue_regs(0) is None"),
    };
    let tx1 = match tx_queue_regs(1) {
        Some(t) => t,
        None => return TestResult::Fail("tx_queue_regs(1) is None"),
    };
    let rx1 = match rx_queue_regs(1) {
        Some(r) => r,
        None => return TestResult::Fail("rx_queue_regs(1) is None"),
    };
    let tx2 = match tx_queue_regs(2) {
        Some(t) => t,
        None => return TestResult::Fail("tx_queue_regs(2) is None"),
    };
    // 1. 1/1 rebuild programs bases, lengths, heads, tails,
    // enables, SRRCTL, FCTRL, RXEN, and the misc vector.
    let mut bank = FakeBank::new();
    if resume_rebuild_plan(&mut bank, &QueueConfig::single(), &[0x1000], &[0x2000]).is_err() {
        return TestResult::Fail("1/1 rebuild failed");
    }
    if bank.read32(tx0.tdbal) != 0x1000
        || bank.read32(tx0.tdbah) != 0
        || bank.read32(tx0.tdlen) != 32 * 16
        || bank.read32(tx0.tdh) != 0
        || bank.read32(tx0.tdt) != 0
        || bank.read32(tx0.txdctl) & TXDCTL_ENABLE == 0
        || bank.read32(rx0.rdbal) != 0x2000
        || bank.read32(rx0.rdbah) != 0
        || bank.read32(rx0.rdlen) != 32 * 16
        || bank.read32(rx0.rdh) != 0
        || bank.read32(rx0.rdt) != 31
        || bank.read32(rx0.srrctl) != SRRCTL_BSIZE_2K
        || bank.read32(rx0.rxdctl) & RXDCTL_ENABLE == 0
        || bank.read32(0x05080) != (FCTRL_BAM | FCTRL_UPE | FCTRL_MPE)
        || bank.read32(0x03000) & 1 == 0
        || bank.read32(0x00880) != 1
    {
        return TestResult::Fail("1/1 rebuild programmed wrong registers");
    }
    // 2. Per-queue composition: a 2/2 config programs queue 1
    // from its own bases and leaves queue 2 untouched (never a
    // hardcoded queue 0).
    let cfg2 = QueueConfig {
        num_tx: 2,
        num_rx: 2,
        ring_len: 32,
    };
    let mut bank = FakeBank::new();
    if resume_rebuild_plan(&mut bank, &cfg2, &[0x1000, 0x3000], &[0x2000, 0x4000]).is_err() {
        return TestResult::Fail("2/2 rebuild failed");
    }
    if bank.read32(tx1.tdbal) != 0x3000
        || bank.read32(tx1.tdlen) != 32 * 16
        || bank.read32(tx1.txdctl) & TXDCTL_ENABLE == 0
        || bank.read32(rx1.rdbal) != 0x4000
        || bank.read32(rx1.rdt) != 31
        || bank.read32(rx1.rxdctl) & RXDCTL_ENABLE == 0
        || bank.read32(tx2.tdbal) != 0
        || bank.read32(tx2.txdctl) & TXDCTL_ENABLE != 0
    {
        return TestResult::Fail("2/2 rebuild did not program per-queue rings");
    }
    // 3. Fail-closed: bad configs and base-count mismatches
    // return Err AND leave the bank untouched (sentinel survives).
    let bad = QueueConfig {
        num_tx: 0,
        num_rx: 1,
        ring_len: 32,
    };
    let mut bank = FakeBank::new();
    bank.write32(tx0.tdbal, 0xDEAD);
    if resume_rebuild_plan(&mut bank, &bad, &[], &[0x2000]).is_ok()
        || bank.read32(tx0.tdbal) != 0xDEAD
    {
        return TestResult::Fail("zero-queue config was not fail-closed");
    }
    let mut bank = FakeBank::new();
    bank.write32(tx0.tdbal, 0xDEAD);
    if resume_rebuild_plan(
        &mut bank,
        &QueueConfig::single(),
        &[0x1000, 0x3000],
        &[0x2000],
    )
    .is_ok()
        || bank.read32(tx0.tdbal) != 0xDEAD
    {
        return TestResult::Fail("base-count mismatch was not fail-closed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_pm_resume_rebuild);

// ── Ethtool fixtures (commit 6) ──────────────────────────────────

fn smoke_ixgbe_ethtool_snapshot() -> TestResult {
    use super::ethtool::{
        read_stats, EthtoolInfo, NicStats, QueueStats, ETHTOOL_DRIVER, ETHTOOL_VERSION,
    };
    use super::queues::RegBank;
    if ETHTOOL_DRIVER != "ixgbe" || ETHTOOL_VERSION != "0.1.0" {
        return TestResult::Fail("ethtool driver identity wrong");
    }
    let mut bank = FakeBank::new();
    bank.write32(0x04074, 123);
    bank.write32(0x04080, 456);
    let stats = read_stats(&bank);
    if stats
        != (NicStats {
            rx_good_packets: 123,
            tx_good_packets: 456,
        })
    {
        return TestResult::Fail("stats snapshot wrong");
    }
    let info = EthtoolInfo {
        driver: ETHTOOL_DRIVER,
        version: ETHTOOL_VERSION,
        mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        mtu: 1500,
        link_up: true,
        num_tx_queues: 1,
        num_rx_queues: 1,
        caps: 0xC0,
        rss_enabled: false,
        vlan_filter_enabled: true,
        wol_supported: true,
        wol_armed: false,
        stats,
        queue_stats: QueueStats::default(),
    };
    let summary = info.summary();
    if !summary.contains("ixgbe 0.1.0")
        || !summary.contains("rx_pkts=123")
        || !summary.contains("tx_pkts=456")
    {
        return TestResult::Fail("ethtool summary missing fields");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_ethtool_snapshot);

// ── EEE control/status (§13f) ──────────────────────────────────────

fn smoke_ixgbe_eee_capability_table() -> TestResult {
    use super::eee::{
        eee_capable, DEV_E610_10G_T, DEV_E610_2_5G_T, DEV_E610_BACKPLANE, DEV_E610_SFP,
        DEV_X550EM_A_1G_T, DEV_X550EM_A_1G_T_L,
    };
    // No in-tree device id is EEE-capable per Linux's switch.
    for did in [
        IXGBE_DEV_82599EB,
        IXGBE_DEV_X540,
        IXGBE_DEV_X550,
        IXGBE_DEV_X550EM_X,
    ] {
        if eee_capable(did) {
            return TestResult::Fail("in-tree device id reported EEE-capable");
        }
    }
    // In-tree X550EM_X (0x15AB) is a different part from
    // X550EM_A_1G_T (0x15E4) and must not be confused with it.
    if IXGBE_DEV_X550EM_X == DEV_X550EM_A_1G_T {
        return TestResult::Fail("X550EM_X collides with X550EM_A_1G_T");
    }
    for did in [
        DEV_X550EM_A_1G_T,
        DEV_X550EM_A_1G_T_L,
        DEV_E610_BACKPLANE,
        DEV_E610_SFP,
        DEV_E610_10G_T,
        DEV_E610_2_5G_T,
    ] {
        if !eee_capable(did) {
            return TestResult::Fail("Linux-capable device id reported incapable");
        }
    }
    if eee_capable(0xFFFF) {
        return TestResult::Fail("unknown device id reported EEE-capable");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_eee_capability_table);

fn smoke_ixgbe_eee_defaults() -> TestResult {
    use super::eee::{
        e610_defaults, x550em_a_defaults, EeeSpeeds, EEE_SPEED_100M, EEE_SPEED_10G, EEE_SPEED_1G,
        EEE_SPEED_2_5G, EEE_SPEED_5G,
    };
    let (sup, adv) = x550em_a_defaults();
    if sup != EeeSpeeds(EEE_SPEED_100M | EEE_SPEED_1G) || adv != sup {
        return TestResult::Fail("X550EM_A defaults are not 100M|1G supported+advertised");
    }
    let (sup, adv) = e610_defaults(true);
    if sup != EeeSpeeds(EEE_SPEED_2_5G) || adv != sup {
        return TestResult::Fail("E610 2.5G_T defaults are not {2.5G}");
    }
    let (sup, adv) = e610_defaults(false);
    if sup != EeeSpeeds(EEE_SPEED_2_5G | EEE_SPEED_5G | EEE_SPEED_10G) || adv != sup {
        return TestResult::Fail("E610 defaults are not {2.5G,5G,10G}");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_eee_defaults);

fn smoke_ixgbe_eee_state_machine() -> TestResult {
    use super::eee::{
        EeeSpeeds, EeeState, LpModes, EEE_SPEED_100M, EEE_SPEED_10G, EEE_SPEED_1G, LP_10000BASE_KR,
        LP_1000BASE_T, LP_100BASE_T,
    };
    let supported = EeeSpeeds(EEE_SPEED_100M | EEE_SPEED_1G);
    let mut state = EeeState::new(supported, supported);
    if !state.enabled() || !state.tx_lpi_enabled() || state.active() {
        return TestResult::Fail("enabled state wrong with no partner modes");
    }
    state.lp_advertised = LpModes(LP_100BASE_T | LP_1000BASE_T);
    if !state.active() {
        return TestResult::Fail("advertised∩partner should be active");
    }
    // A 10G partner bit alone cannot activate a 100M|1G advertisement.
    state.lp_advertised = LpModes(LP_10000BASE_KR);
    if state.active() {
        return TestResult::Fail("KR partner mode wrongly activates T advertisement");
    }
    // Disabling clears the advertised set (Linux set_eee semantics).
    state.set_enabled(false);
    if state.enabled() || state.tx_lpi_enabled() || !state.advertised.is_empty() {
        return TestResult::Fail("disable did not clear advertised set");
    }
    state.lp_advertised = LpModes(LP_100BASE_T);
    if state.active() {
        return TestResult::Fail("disabled state wrongly active");
    }
    // Re-enabling restores advertised = supported, and a 10G
    // advertisement intersects a 10G partner bit.
    state.set_enabled(true);
    let mut state10 = EeeState::new(EeeSpeeds(EEE_SPEED_10G), EeeSpeeds(EEE_SPEED_10G));
    state10.lp_advertised = LpModes(LP_10000BASE_KR);
    if state10.active() {
        return TestResult::Fail("10G T advertisement wrongly active on KR partner");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_eee_state_machine);

fn smoke_ixgbe_eee_ud2_decode() -> TestResult {
    use super::eee::{
        lp_mode_names, lp_modes_from_ud2, LpModes, LP_10000BASE_KR, LP_1000BASE_T, LP_100BASE_T,
        UD_2_100M_TX_EEE, UD_2_10G_KR_EEE, UD_2_1G_T_EEE,
    };
    let modes = lp_modes_from_ud2(UD_2_100M_TX_EEE | UD_2_1G_T_EEE | UD_2_10G_KR_EEE);
    if modes != LpModes(LP_100BASE_T | LP_1000BASE_T | LP_10000BASE_KR) {
        return TestResult::Fail("UD_2 decode wrong");
    }
    let names = lp_mode_names(modes);
    if names != ["100baseT", "1000baseT", "10000baseKR"] {
        return TestResult::Fail("UD_2 mode names wrong");
    }
    if !lp_modes_from_ud2(0).is_empty() || !lp_mode_names(LpModes::EMPTY).is_empty() {
        return TestResult::Fail("empty UD_2 word decodes non-empty");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_eee_ud2_decode);

fn smoke_ixgbe_eee_validate() -> TestResult {
    use super::eee::{
        validate_request, EeeError, EeeRequest, EeeSpeeds, EeeState, EEE_SPEED_100M, EEE_SPEED_1G,
    };
    let supported = EeeSpeeds(EEE_SPEED_100M | EEE_SPEED_1G);
    let stored = EeeState::new(supported, supported);
    let base = EeeRequest {
        enabled: false,
        tx_lpi_enabled: true,
        tx_lpi_timer: 0,
        advertised: supported,
    };
    // Only the enabled flag may move.
    if validate_request(true, &stored, &base) != Ok(()) {
        return TestResult::Fail("valid disable request rejected");
    }
    if validate_request(false, &stored, &base) != Err(EeeError::NotCapable) {
        return TestResult::Fail("incapable device not rejected first");
    }
    let mut req = base;
    req.tx_lpi_enabled = false;
    if validate_request(true, &stored, &req) != Err(EeeError::TxLpiMismatch) {
        return TestResult::Fail("TX-LPI enable change not rejected");
    }
    req = base;
    req.tx_lpi_timer = 7;
    if validate_request(true, &stored, &req) != Err(EeeError::TxLpiTimerMismatch) {
        return TestResult::Fail("TX-LPI timer change not rejected");
    }
    req = base;
    req.advertised = EeeSpeeds(EEE_SPEED_100M);
    if validate_request(true, &stored, &req) != Err(EeeError::AdvertisedMismatch) {
        return TestResult::Fail("advertised-set change not rejected");
    }
    req = base;
    req.enabled = true;
    if validate_request(true, &stored, &req) != Err(EeeError::AlreadyEnabled) {
        return TestResult::Fail("no-op enable not reported already-enabled");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_eee_validate);

fn smoke_ixgbe_eee_aci_cap() -> TestResult {
    use super::eee::{
        aci_eee_cap, EeeSpeeds, ACI_EEE_EN_10GBASE_T, ACI_EEE_EN_2_5GBASE_T, ACI_EEE_EN_5GBASE_T,
        EEE_SPEED_100M, EEE_SPEED_10G, EEE_SPEED_1G, EEE_SPEED_2_5G, EEE_SPEED_5G,
    };
    let full = EeeSpeeds(EEE_SPEED_2_5G | EEE_SPEED_5G | EEE_SPEED_10G);
    if aci_eee_cap(full) != ACI_EEE_EN_2_5GBASE_T | ACI_EEE_EN_5GBASE_T | ACI_EEE_EN_10GBASE_T
        || aci_eee_cap(full) != 0x1804
    {
        return TestResult::Fail("ACI cap for {2.5G,5G,10G} is not 0x1804");
    }
    // E610 maps nothing below 2.5G, even when advertised.
    if aci_eee_cap(EeeSpeeds(EEE_SPEED_100M | EEE_SPEED_1G)) != 0 {
        return TestResult::Fail("ACI cap wrongly maps 100M/1G");
    }
    if aci_eee_cap(EeeSpeeds::EMPTY) != 0 {
        return TestResult::Fail("ACI cap non-zero for empty set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_eee_aci_cap);

fn smoke_ixgbe_eee_ls_modes() -> TestResult {
    use super::eee::{
        speed_mode_names, EeeSpeeds, EEE_SPEED_100M, EEE_SPEED_10G, EEE_SPEED_10M, EEE_SPEED_1G,
        EEE_SPEED_2_5G, EEE_SPEED_5G,
    };
    let all = EeeSpeeds(
        EEE_SPEED_10M
            | EEE_SPEED_100M
            | EEE_SPEED_1G
            | EEE_SPEED_2_5G
            | EEE_SPEED_5G
            | EEE_SPEED_10G,
    );
    if speed_mode_names(all)
        != [
            "10baseT",
            "100baseT",
            "1000baseT",
            "2500baseT",
            "5000baseT",
            "10000baseT",
        ]
    {
        return TestResult::Fail("LS mode names wrong or out of order");
    }
    if !speed_mode_names(EeeSpeeds::EMPTY).is_empty() {
        return TestResult::Fail("empty speed set names non-empty");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_eee_ls_modes);

// ── Flow Director ────────────────────────────────────────────────────

// Test bank modeling documented hardware completion behavior: FDIRCTRL
// reads report INIT_DONE set (hardware sets it when init completes),
// FDIRCMD reads report the command field cleared (hardware clears it
// when the command completes) plus FILTER_VALID when the query flag is
// set (hardware reports a present filter). Raw stored values stay
// readable via `stored` so the write conversation is still pinned.
struct FdirBank {
    inner: FakeBank,
    query_valid: bool,
}

impl FdirBank {
    fn new(query_valid: bool) -> Self {
        Self {
            inner: FakeBank::new(),
            query_valid,
        }
    }

    fn stored(&self, offset: u64) -> u32 {
        use super::queues::RegBank;
        self.inner.read32(offset)
    }
}

impl super::queues::RegBank for FdirBank {
    fn read32(&self, offset: u64) -> u32 {
        use super::fdir::{FDIRCMD_CMD_MASK, FDIRCMD_FILTER_VALID, FDIRCTRL_INIT_DONE};
        use super::fdir::{REG_FDIRCMD, REG_FDIRCTRL};
        let v = self.inner.read32(offset);
        if offset == REG_FDIRCTRL {
            v | FDIRCTRL_INIT_DONE
        } else if offset == REG_FDIRCMD {
            (v & !FDIRCMD_CMD_MASK)
                | if self.query_valid {
                    FDIRCMD_FILTER_VALID
                } else {
                    0
                }
        } else {
            v
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        self.inner.write32(offset, value);
    }
}

fn smoke_ixgbe_fdir_hash_oracles() -> TestResult {
    use super::fdir::{perfect_bucket_hash, perfect_stream, sig_hash, FdirPerfectInput};
    // Python oracles, re-implemented independently from the Linux
    // macro text (see lane notes): sig = combined signature+bucket.
    if sig_hash(0x0002_0000, 0x0000_0003) != 0x1b79_58a1 {
        return TestResult::Fail("sig hash oracle 1 mismatch");
    }
    if sig_hash(0x0305_0123, 0xDEAD_BEEF) != 0x7c87_3ba7 {
        return TestResult::Fail("sig hash oracle 2 mismatch");
    }
    if sig_hash(0x0002_0000, 0x0000_0000) != 0x6a12_4a52 {
        return TestResult::Fail("sig hash oracle 3 mismatch");
    }
    // Perfect bucket oracles (same Python implementation).
    let input = FdirPerfectInput {
        vm_pool: 0,
        flow_type: super::fdir::FLOW_TYPE_TCPV4,
        vlan_id: 100,
        src_ip: 0xC0A8_010A,
        dst_ip: 0xC0A8_0114,
        src_port: 12345,
        dst_port: 80,
        flex_bytes: 0,
        bkt_hash: 0,
    };
    if perfect_bucket_hash(&perfect_stream(&input)) != 0x1f6c {
        return TestResult::Fail("perfect bucket oracle 1 mismatch");
    }
    let mut words = [0u32; 11];
    words[0] = 0x0503_0000;
    if perfect_bucket_hash(&words) != 0x03bd {
        return TestResult::Fail("perfect bucket oracle 2 mismatch");
    }
    let words = [0xFFFF_FFFFu32; 11];
    if perfect_bucket_hash(&words) != 0x0318 {
        return TestResult::Fail("perfect bucket oracle 3 mismatch");
    }
    // Mask application is word-wise AND.
    let masked = super::fdir::apply_mask(&[0xFFFF_FFFFu32; 11], &[0x0F0F_0F0Fu32; 11]);
    if masked != [0x0F0F_0F0Fu32; 11] {
        return TestResult::Fail("apply_mask is not word-wise AND");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_hash_oracles);

fn smoke_ixgbe_fdir_ctrl_words() -> TestResult {
    use super::fdir::{fdirctrl_perfect, fdirctrl_signature, FdirPballoc};
    // Signature: pballoc 1 + flex 6<<16 + maxlen 0xA<<24 + thresh 4<<28.
    if fdirctrl_signature(FdirPballoc::K64) != 0x4A06_0001 {
        return TestResult::Fail("signature FDIRCTRL word wrong");
    }
    // Perfect adds PERFECT_MATCH + drop queue 127<<8.
    if fdirctrl_perfect(FdirPballoc::K64) != 0x4A06_7F11 {
        return TestResult::Fail("perfect FDIRCTRL word wrong");
    }
    if fdirctrl_signature(FdirPballoc::K256) & 0x3 != 0x3 {
        return TestResult::Fail("256K pballoc bits wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_ctrl_words);

fn smoke_ixgbe_fdir_init_conversation() -> TestResult {
    use super::fdir::{init_perfect, init_signature, FdirPballoc};
    use super::fdir::{REG_FDIRCTRL, REG_FDIRHKEY, REG_FDIRSKEY};
    let mut bank = FdirBank::new(false);
    if !init_signature(&mut bank, FdirPballoc::K64) {
        return TestResult::Fail("signature init never observed INIT_DONE");
    }
    if bank.stored(REG_FDIRHKEY) != 0x3DAD_14E2 || bank.stored(REG_FDIRSKEY) != 0x174D_3614 {
        return TestResult::Fail("FDIR hash keys not primed");
    }
    if bank.stored(REG_FDIRCTRL) != 0x4A06_0001 {
        return TestResult::Fail("signature FDIRCTRL write wrong");
    }
    if !init_perfect(&mut bank, FdirPballoc::K64) {
        return TestResult::Fail("perfect init never observed INIT_DONE");
    }
    if bank.stored(REG_FDIRCTRL) != 0x4A06_7F11 {
        return TestResult::Fail("perfect FDIRCTRL write wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_init_conversation);

fn smoke_ixgbe_fdir_mask_words() -> TestResult {
    use super::fdir::{mask_words, set_input_mask, FdirMask};
    use super::fdir::{
        REG_FDIRDIP4M, REG_FDIRM, REG_FDIRSCTPM, REG_FDIRSIP4M, REG_FDIRTCPM, REG_FDIRUDPM,
    };
    // Match-everything mask: only DIPv6 set; port/IP registers zero.
    let all_match = FdirMask {
        vm_pool: 0x7F,
        flow_type: 0x03,
        vlan_id: 0xEFFF,
        src_port: 0xFFFF,
        dst_port: 0xFFFF,
        flex_bytes: 0xFFFF,
        src_ip: 0xFFFF_FFFF,
        dst_ip: 0xFFFF_FFFF,
    };
    let (fdirm, port, src, dst) = match mask_words(&all_match) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("match-all mask rejected"),
    };
    if fdirm != 0x20 || port != 0 || src != 0 || dst != 0 {
        return TestResult::Fail("match-all mask words wrong");
    }
    // Mask-everything mask: all FDIRM bits; inverted registers all ones.
    let all_masked = FdirMask {
        vm_pool: 0x00,
        flow_type: 0x00,
        vlan_id: 0x0000,
        src_port: 0,
        dst_port: 0,
        flex_bytes: 0x0000,
        src_ip: 0,
        dst_ip: 0,
    };
    let (fdirm, port, src, dst) = match mask_words(&all_masked) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("mask-all mask rejected"),
    };
    if fdirm != 0x3F || port != 0xFFFF_FFFF || src != 0xFFFF_FFFF || dst != 0xFFFF_FFFF {
        return TestResult::Fail("mask-all mask words wrong");
    }
    // Validation rejects each bad field.
    let mut bad = all_match;
    bad.vm_pool = 0x40;
    if mask_words(&bad).is_ok() {
        return TestResult::Fail("bad vm_pool mask accepted");
    }
    let mut bad = all_match;
    bad.flow_type = 0x01;
    if mask_words(&bad).is_ok() {
        return TestResult::Fail("bad flow_type mask accepted");
    }
    let mut bad = all_match;
    bad.vlan_id = 0x0123;
    if mask_words(&bad).is_ok() {
        return TestResult::Fail("bad vlan mask accepted");
    }
    let mut bad = all_match;
    bad.flex_bytes = 0x1234;
    if mask_words(&bad).is_ok() {
        return TestResult::Fail("bad flex mask accepted");
    }
    let mut bad = all_match;
    bad.flow_type = 0x00;
    bad.src_port = 1;
    if mask_words(&bad).is_ok() {
        return TestResult::Fail("ports with masked L4 accepted");
    }
    // Conversation: SCTP register written only when sctp=true. The
    // mask-all mask makes the port register all-ones, so a written
    // SCTP register is distinguishable from a never-written one.
    let mut bank = FdirBank::new(false);
    if set_input_mask(&mut bank, &all_masked, false).is_err() {
        return TestResult::Fail("set_input_mask failed");
    }
    if bank.stored(REG_FDIRM) != 0x3F
        || bank.stored(REG_FDIRTCPM) != 0xFFFF_FFFF
        || bank.stored(REG_FDIRUDPM) != 0xFFFF_FFFF
        || bank.stored(REG_FDIRSIP4M) != 0xFFFF_FFFF
        || bank.stored(REG_FDIRDIP4M) != 0xFFFF_FFFF
        || bank.stored(REG_FDIRSCTPM) != 0
    {
        return TestResult::Fail("mask register conversation wrong (no SCTP)");
    }
    let mut bank = FdirBank::new(false);
    if set_input_mask(&mut bank, &all_masked, true).is_err() {
        return TestResult::Fail("set_input_mask (SCTP) failed");
    }
    if bank.stored(REG_FDIRSCTPM) != 0xFFFF_FFFF {
        return TestResult::Fail("SCTP mask register not written");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_mask_words);

fn smoke_ixgbe_fdir_perfect_conversation() -> TestResult {
    use super::fdir::REG_FDIRSIPV6_BASE;
    use super::fdir::{add_perfect, FdirPerfectInput, FLOW_TYPE_TCPV4};
    use super::fdir::{
        REG_FDIRCMD, REG_FDIRHASH, REG_FDIRIPDA, REG_FDIRIPSA, REG_FDIRPORT, REG_FDIRVLAN,
    };
    let input = FdirPerfectInput {
        vm_pool: 0,
        flow_type: FLOW_TYPE_TCPV4,
        vlan_id: 100,
        src_ip: 0xC0A8_010A,
        dst_ip: 0xC0A8_0114,
        src_port: 12345,
        dst_port: 80,
        flex_bytes: 0,
        bkt_hash: 0x1f6c,
    };
    let mut bank = FdirBank::new(false);
    if add_perfect(&mut bank, &input, 7, 3).is_err() {
        return TestResult::Fail("add_perfect failed");
    }
    if bank.stored(REG_FDIRSIPV6_BASE) != 0xC0A8_010A
        || bank.stored(REG_FDIRSIPV6_BASE + 4) != 0
        || bank.stored(REG_FDIRSIPV6_BASE + 8) != 0
        || bank.stored(REG_FDIRIPSA) != 0xC0A8_010A
        || bank.stored(REG_FDIRIPDA) != 0xC0A8_0114
        || bank.stored(REG_FDIRPORT) != 0x0050_3039
        || bank.stored(REG_FDIRVLAN) != 0x0000_0064
        || bank.stored(REG_FDIRHASH) != 0x0007_1f6c
        || bank.stored(REG_FDIRCMD) != 0x0003_8849
    {
        return TestResult::Fail("perfect add register conversation wrong");
    }
    // Drop-queue add sets the DROP bit.
    let mut bank = FdirBank::new(false);
    if add_perfect(&mut bank, &input, 0, 127).is_err() {
        return TestResult::Fail("drop-queue add failed");
    }
    if bank.stored(REG_FDIRCMD) != 0x007F_8A49 {
        return TestResult::Fail("drop-queue FDIRCMD wrong");
    }
    // Guards: IPv6 flow type and queue > 127 rejected.
    let mut bad = input;
    bad.flow_type = super::fdir::FLOW_TYPE_TCPV6;
    let mut bank = FdirBank::new(false);
    if add_perfect(&mut bank, &bad, 0, 3).is_ok() {
        return TestResult::Fail("IPv6 perfect add accepted");
    }
    let mut bank = FdirBank::new(false);
    if add_perfect(&mut bank, &input, 0, 128).is_ok() {
        return TestResult::Fail("queue 128 perfect add accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_perfect_conversation);

fn smoke_ixgbe_fdir_erase_conversation() -> TestResult {
    use super::fdir::{erase_perfect, REG_FDIRCMD, REG_FDIRHASH};
    // Absent filter: query issued, no remove.
    let mut bank = FdirBank::new(false);
    if erase_perfect(&mut bank, 0x1f6c, 7).is_err() {
        return TestResult::Fail("erase (absent) failed");
    }
    if bank.stored(REG_FDIRCMD) != 0x0000_0003 || bank.stored(REG_FDIRHASH) != 0x0007_1f6c {
        return TestResult::Fail("erase (absent) conversation wrong");
    }
    // Present filter: query then remove.
    let mut bank = FdirBank::new(true);
    if erase_perfect(&mut bank, 0x1f6c, 7).is_err() {
        return TestResult::Fail("erase (present) failed");
    }
    if bank.stored(REG_FDIRCMD) != 0x0000_0002 || bank.stored(REG_FDIRHASH) != 0x0007_1f6c {
        return TestResult::Fail("erase (present) conversation wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_erase_conversation);

fn smoke_ixgbe_fdir_signature_conversation() -> TestResult {
    use super::fdir::{add_signature, REG_FDIRCMD, REG_FDIRHASH};
    // Oracle input: pool 0, TCPV4, vlan 0; common = 10.0.0.1 ^ 10.0.0.2.
    let mut bank = FdirBank::new(false);
    if add_signature(&mut bank, 0x0002_0000, 0x0000_0003, 0x02, 5).is_err() {
        return TestResult::Fail("add_signature failed");
    }
    if bank.stored(REG_FDIRHASH) != 0x1b79_58a1 || bank.stored(REG_FDIRCMD) != 0x0005_8849 {
        return TestResult::Fail("signature add conversation wrong");
    }
    // Tunnel bit sets TUNNEL_FILTER; base type still TCPV4.
    let mut bank = FdirBank::new(false);
    if add_signature(&mut bank, 0x0002_0000, 0x0000_0003, 0x12, 5).is_err() {
        return TestResult::Fail("tunnel signature add failed");
    }
    if bank.stored(REG_FDIRCMD) != 0x0085_8849 {
        return TestResult::Fail("tunnel FDIRCMD wrong");
    }
    // Guards: bare IPv4, bare IPv6, queue > 127 rejected.
    let mut bank = FdirBank::new(false);
    if add_signature(&mut bank, 0x0002_0000, 0x0000_0003, 0x00, 5).is_ok() {
        return TestResult::Fail("bare IPv4 signature accepted");
    }
    let mut bank = FdirBank::new(false);
    if add_signature(&mut bank, 0x0002_0000, 0x0000_0003, 0x04, 5).is_ok() {
        return TestResult::Fail("bare IPv6 signature accepted");
    }
    let mut bank = FdirBank::new(false);
    if add_signature(&mut bank, 0x0002_0000, 0x0000_0003, 0x02, 200).is_ok() {
        return TestResult::Fail("queue 200 signature accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_signature_conversation);

fn smoke_ixgbe_fdir_reinit_conversation() -> TestResult {
    use super::fdir::{reinit_tables, REG_FDIRCMD, REG_FDIRCTRL, REG_FDIRFREE, REG_FDIRHASH};
    use super::queues::RegBank;
    let mut bank = FdirBank::new(false);
    bank.write32(REG_FDIRCTRL, 0x4A06_7F11);
    bank.write32(REG_FDIRCMD, 0x0000_8001);
    if reinit_tables(&mut bank).is_err() {
        return TestResult::Fail("reinit failed");
    }
    // INIT_DONE cleared from the restored CTRL; hash + free cleared;
    // CLEARHT toggled away, CMD field cleared by the completion model.
    if bank.stored(REG_FDIRCTRL) != 0x4A06_7F11
        || bank.stored(REG_FDIRHASH) != 0
        || bank.stored(REG_FDIRFREE) != 0
        || bank.stored(REG_FDIRCMD) != 0x0000_8000
    {
        return TestResult::Fail("reinit register conversation wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_reinit_conversation);

fn smoke_ixgbe_fdir_stats() -> TestResult {
    use super::fdir::{
        stats, REG_FDIRFREE, REG_FDIRFSTAT, REG_FDIRLEN, REG_FDIRMATCH, REG_FDIRMISS, REG_FDIRUSTAT,
    };
    use super::queues::RegBank;
    let mut bank = FdirBank::new(false);
    bank.write32(REG_FDIRMATCH, 11);
    bank.write32(REG_FDIRMISS, 22);
    bank.write32(REG_FDIRUSTAT, 33);
    bank.write32(REG_FDIRFSTAT, 44);
    bank.write32(REG_FDIRLEN, 5);
    bank.write32(REG_FDIRFREE, 0x0003_1234);
    let s = stats(&mut bank);
    if s.matched != 11 || s.missed != 22 || s.ustat != 33 || s.fstat != 44 || s.len != 5 {
        return TestResult::Fail("stats values wrong");
    }
    if s.free_count() != 0x1234 || s.collision_count() != 0x0003 {
        return TestResult::Fail("FDIRFREE decomposition wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_fdir_stats);

// ── DCB fixtures ───────────────────────────────────────────────────

fn dcb_tc(refill: u16, max: u16, bwg_id: u8, prio: super::dcb::PrioType) -> super::dcb::TcCredits {
    super::dcb::TcCredits {
        refill,
        max,
        bwg_id,
        prio_type: prio,
    }
}

fn smoke_ixgbe_dcb_register_conversation_8tc() -> TestResult {
    use super::dcb::*;
    use super::queues::RegBank;
    use super::IXGBE_DEV_82599EB;
    let mut tc = [dcb_tc(32, 256, 0, PrioType::None); MAX_TRAFFIC_CLASS];
    for (i, slot) in tc.iter_mut().enumerate() {
        *slot = dcb_tc(
            32 * (i as u16 + 1),
            256 * (i as u16 + 1),
            i as u8,
            match i % 3 {
                0 => PrioType::Link,
                1 => PrioType::Group,
                _ => PrioType::None,
            },
        );
    }
    let mut high = [0u32; MAX_TRAFFIC_CLASS];
    let mut low = [0u32; MAX_TRAFFIC_CLASS];
    for i in 0..MAX_TRAFFIC_CLASS {
        high[i] = 16 + i as u32;
        low[i] = 8 + i as u32;
    }
    let cfg = DcbConfig {
        num_tcs: 8,
        tc,
        prio_to_tc: [0, 1, 2, 3, 4, 5, 6, 7],
        // UPs 0 and 2: TCs 0 and 2 PFC-enabled, the rest guard-pathed.
        pfc_enable: 0b0000_0101,
        high_water: high,
        low_water: low,
        pause_time: 160,
    };
    let mut bank = FakeBank::new();
    if cfg.apply(&mut bank, IXGBE_DEV_82599EB).is_err() {
        return TestResult::Fail("8-TC DCB apply failed");
    }
    // Mode + buffers.
    if bank.read32(REG_MTQC) != 0x0000_000D {
        return TestResult::Fail("MTQC not RT_ENA|8TC_8TQ");
    }
    if bank.read32(REG_SECTXMINIFG) != 0x0000_1F00 {
        return TestResult::Fail("SECTXMINIFG DCB IFG not set");
    }
    if bank.read32(REG_RXPBSIZE_BASE) != 0x0001_0000
        || bank.read32(REG_TXPBSIZE_BASE) != 0x0000_5000
        || bank.read32(REG_TXPBTHRESH_BASE) != 10
    {
        return TestResult::Fail("packet buffers not 64K/20K/thresh-10");
    }
    // Arbiters.
    if bank.read32(REG_RTRPCS) != 0x0000_0006
        || bank.read32(REG_RTRUP2TC) != 0x00FA_C688
        || bank.read32(REG_RTTUP2TC) != 0x00FA_C688
        || bank.read32(REG_RTTDCS) != 0x0000_0011
        || bank.read32(REG_RTTPCS) != 0x0100_0120
    {
        return TestResult::Fail("arbiter control/UP-map words wrong");
    }
    if bank.read32(REG_RTRPT4C_BASE) != 0x8010_0020
        || bank.read32(REG_RTRPT4C_BASE + 4) != 0x0020_0240
        || bank.read32(REG_RTTDT2C_BASE + 4) != 0x4020_0240
        || bank.read32(REG_RTTPT2C_BASE + 8) != 0x0030_0460
    {
        return TestResult::Fail("per-TC credit words wrong");
    }
    if bank.read32(REG_RTTDQSEL) != 127 || bank.read32(REG_RTTDT1C) != 0 {
        return TestResult::Fail("TX desc queue-credit clear incomplete");
    }
    // PFC: 82599 has no per-TC bits, only the single RPFCE bit.
    if bank.read32(REG_FCCFG) != 0x0000_0010 || bank.read32(REG_MFLCN) != 0x0000_0006 {
        return TestResult::Fail("FCCFG/MFLCN wrong for 82599");
    }
    if bank.read32(REG_FCRTL_BASE) != 0x8000_2000
        || bank.read32(REG_FCRTH_BASE) != 0x8000_4000
        || bank.read32(REG_FCRTL_BASE + 8) != 0x8000_2800
        || bank.read32(REG_FCRTH_BASE + 8) != 0x8000_4800
    {
        return TestResult::Fail("enabled-TC watermarks wrong");
    }
    if bank.read32(REG_FCRTL_BASE + 4) != 0 || bank.read32(REG_FCRTH_BASE + 4) != 0x0000_A000 {
        return TestResult::Fail("disabled-TC guard path wrong");
    }
    if bank.read32(REG_FCTTV_BASE) != 0x00A0_00A0 || bank.read32(REG_FCRTV) != 80 {
        return TestResult::Fail("pause time / refresh threshold wrong");
    }
    // TC statistics mapping.
    if bank.read32(REG_RQSMR_BASE) != 0
        || bank.read32(REG_RQSMR_BASE + 16) != 0x0101_0101
        || bank.read32(REG_RQSMR_BASE + 124) != 0x0707_0707
        || bank.read32(REG_TQSM_BASE) != 0
        || bank.read32(REG_TQSM_BASE + 32) != 0x0101_0101
        || bank.read32(REG_TQSM_BASE + 64) != 0x0202_0202
        || bank.read32(REG_TQSM_BASE + 124) != 0x0707_0707
    {
        return TestResult::Fail("TC statistics mapping wrong");
    }
    if read_up_to_tc(&bank) != [0, 1, 2, 3, 4, 5, 6, 7] {
        return TestResult::Fail("RTRUP2TC read-back disagrees");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/ixgbe",
    smoke_ixgbe_dcb_register_conversation_8tc
);

fn smoke_ixgbe_dcb_register_conversation_4tc_x540() -> TestResult {
    use super::dcb::*;
    use super::queues::RegBank;
    use super::IXGBE_DEV_X540;
    let tc = [dcb_tc(100, 1000, 0, PrioType::None); MAX_TRAFFIC_CLASS];
    let cfg = DcbConfig {
        num_tcs: 4,
        tc,
        prio_to_tc: [0, 0, 1, 1, 2, 2, 3, 3],
        pfc_enable: 0xFF,
        high_water: [32; MAX_TRAFFIC_CLASS],
        low_water: [16; MAX_TRAFFIC_CLASS],
        pause_time: 0,
    };
    let mut bank = FakeBank::new();
    if cfg.apply(&mut bank, IXGBE_DEV_X540).is_err() {
        return TestResult::Fail("4-TC X540 DCB apply failed");
    }
    if bank.read32(REG_MTQC) != 0x0000_0009 {
        return TestResult::Fail("MTQC not RT_ENA|4TC_4TQ");
    }
    // X540 packet buffer is 384 KiB: 96 KiB RX / 40 KiB TX per TC.
    if bank.read32(REG_RXPBSIZE_BASE) != 0x0001_8000
        || bank.read32(REG_TXPBSIZE_BASE) != 0x0000_A000
        || bank.read32(REG_TXPBTHRESH_BASE) != 30
    {
        return TestResult::Fail("X540 packet buffers not 96K/40K/thresh-30");
    }
    // Unused TCs cleared.
    if bank.read32(REG_RXPBSIZE_BASE + 16) != 0
        || bank.read32(REG_TXPBSIZE_BASE + 16) != 0
        || bank.read32(REG_TXPBTHRESH_BASE + 16) != 0
    {
        return TestResult::Fail("unused TC buffers not cleared");
    }
    if bank.read32(REG_RTRUP2TC) != 0x006D_2240 {
        return TestResult::Fail("4-TC UP map wrong");
    }
    // X540 programs the per-TC RPFCE bits plus the single bit.
    if bank.read32(REG_MFLCN) != 0x0000_0FF6 {
        return TestResult::Fail("X540 MFLCN per-TC bits wrong");
    }
    // All TCs 0..3 PFC-enabled (max_tc = 3); TCs 4..7 zeroed.
    if bank.read32(REG_FCRTH_BASE) != (32 << 10) | 0x8000_0000
        || bank.read32(REG_FCRTL_BASE + 16) != 0
        || bank.read32(REG_FCRTH_BASE + 16) != 0
    {
        return TestResult::Fail("4-TC PFC threshold range wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/ixgbe",
    smoke_ixgbe_dcb_register_conversation_4tc_x540
);

fn smoke_ixgbe_dcb_validation_rejects() -> TestResult {
    use super::dcb::*;
    use super::queues::RegBank;
    use super::IXGBE_DEV_82599EB;
    let base = DcbConfig {
        num_tcs: 8,
        tc: [dcb_tc(100, 1000, 0, PrioType::None); MAX_TRAFFIC_CLASS],
        prio_to_tc: [0, 1, 2, 3, 4, 5, 6, 7],
        pfc_enable: 0,
        high_water: [16; MAX_TRAFFIC_CLASS],
        low_water: [8; MAX_TRAFFIC_CLASS],
        pause_time: 0,
    };
    let mut bad_num = base.clone();
    bad_num.num_tcs = 2;
    let mut bad_tc = base.clone();
    bad_tc.prio_to_tc[0] = 8;
    let mut bad_bwg = base.clone();
    bad_bwg.tc[0].bwg_id = 8;
    let mut bad_refill = base.clone();
    bad_refill.tc[0].refill = 512;
    let mut bad_max = base.clone();
    bad_max.tc[0].max = 4096;
    let mut bad_water = base.clone();
    bad_water.high_water[0] = 0x0040_0000;
    let cases = [
        (bad_num, DcbError::NumTcs),
        (bad_tc, DcbError::TcIndex),
        (bad_bwg, DcbError::BwgId),
        (bad_refill, DcbError::Refill),
        (bad_max, DcbError::Max),
        (bad_water, DcbError::Water),
    ];
    for (cfg, want) in cases {
        let mut bank = FakeBank::new();
        match cfg.apply(&mut bank, IXGBE_DEV_82599EB) {
            Err(got) if got == want => {}
            _ => return TestResult::Fail("DCB validation missed a bad config"),
        }
        // Validation precedes every write: the bank stays pristine.
        if bank.read32(REG_MTQC) != 0 || bank.read32(REG_RTRPCS) != 0 {
            return TestResult::Fail("rejected DCB config wrote registers");
        }
    }
    let mut bank = FakeBank::new();
    if base.apply(&mut bank, 0xFFFF).is_ok() {
        return TestResult::Fail("DCB apply accepted an ungrounded device");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_dcb_validation_rejects);

fn smoke_ixgbe_dcb_ieee_credits() -> TestResult {
    use super::dcb::*;
    let bw = [50u8, 30, 20, 0, 0, 0, 0, 0];
    let (refill, max) = ieee_credits(&bw, 1518);
    if refill != [50, 30, 20, 12, 12, 12, 12, 12] {
        return TestResult::Fail("IEEE refill credits wrong");
    }
    if max != [2047, 1228, 819, 12, 12, 12, 12, 12] {
        return TestResult::Fail("IEEE max credits wrong");
    }
    // Zero-bandwidth TCs still get the minimum credit; a tiny
    // bandwidth still clears the minimum-frame floor via the clamp.
    let (refill2, _) = ieee_credits(&[1, 0, 0, 0, 0, 0, 0, 0], 9000);
    // min_credit = (4500 + 63) / 64 = 71; multiplier = 71/1 + 1 = 72.
    if refill2[0] != 72 || refill2[1] != 71 {
        return TestResult::Fail("IEEE credit floor wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_dcb_ieee_credits);

// ── TX VLAN insertion + TSO frame-cap fix (#1269) ─────────────────

fn smoke_ixgbe_tx_vle_and_ctxt_vlan() -> TestResult {
    if ADVTXD_DCMD_VLE != 0x4000_0000 {
        return TestResult::Fail("VLE bit wrong");
    }
    let cw = AdvTxDesc::ctrl_word(0x40) | ADVTXD_DCMD_VLE;
    if cw & ADVTXD_DCMD_VLE == 0 || cw & 0xFFFF != 0x40 {
        return TestResult::Fail("VLE ctrl word wrong");
    }
    let v = AdvTxCtxtDesc::new_vlan(0x1234);
    if v.vlan_macip_lens != (0x1234u32 << 16) | (14u32 << 9) {
        return TestResult::Fail("vlan ctxt vlan_macip_lens wrong");
    }
    if v.type_tucmd_mlhl != ADVTXD_DCMD_DEXT | ADVTXD_DTYP_CTXT {
        return TestResult::Fail("vlan ctxt type wrong");
    }
    if v.mss_l4len_idx != 0 || v.seqnum_seed != 0 {
        return TestResult::Fail("vlan ctxt must zero the unused fields");
    }
    let t = AdvTxCtxtDesc::new_tso_v4(14, 20, 20, 1460, Some(0x00AB));
    if t.vlan_macip_lens != 20u32 | (14u32 << 9) | (0x00ABu32 << 16) {
        return TestResult::Fail("tso+vlan ctxt vlan_macip_lens wrong");
    }
    if t.type_tucmd_mlhl
        != ADVTXD_DCMD_DEXT | ADVTXD_DTYP_CTXT | ADVTXD_TUCMD_IPV4 | ADVTXD_TUCMD_L4T_TCP
    {
        return TestResult::Fail("tso ctxt type wrong");
    }
    if t.mss_l4len_idx != (20u32 << 8) | (1460u32 << 16) {
        return TestResult::Fail("tso ctxt mss_l4len wrong");
    }
    let t0 = AdvTxCtxtDesc::new_tso_v4(14, 20, 20, 1460, None);
    if t0.vlan_macip_lens & 0xFFFF_0000 != 0 {
        return TestResult::Fail("tso ctxt without vlan must clear tag bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_tx_vle_and_ctxt_vlan);

fn smoke_ixgbe_tx_tso_parse() -> TestResult {
    // Crafted IPv4/TCP frame: 14 eth + 20 IP + 20 TCP + 46 payload.
    let mut f = alloc::vec![0u8; 100];
    f[12] = 0x08;
    f[13] = 0x00;
    f[14] = 0x45;
    f[14 + 9] = 6;
    f[14 + 20 + 12] = 0x50;
    let h = match parse_tso_headers(&f, f.len()) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("valid tso frame rejected"),
    };
    if h.mac_len != 14 || h.ip_len != 20 || h.l4_len != 20 {
        return TestResult::Fail("tso header lengths wrong");
    }
    // IP options (IHL 6) + TCP options (doff 6).
    let mut g = alloc::vec![0u8; 120];
    g[12] = 0x08;
    g[13] = 0x00;
    g[14] = 0x46;
    g[14 + 9] = 6;
    g[14 + 24 + 12] = 0x60;
    let h = match parse_tso_headers(&g, g.len()) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("options tso frame rejected"),
    };
    if h.ip_len != 24 || h.l4_len != 24 {
        return TestResult::Fail("options header lengths wrong");
    }
    // Rejections.
    if parse_tso_headers(&f[..40], 40).is_ok() {
        return TestResult::Fail("short frame accepted");
    }
    let mut t = f.clone();
    t[12] = 0x81;
    t[13] = 0x00;
    if parse_tso_headers(&t, t.len()).is_ok() {
        return TestResult::Fail("tagged frame accepted");
    }
    let mut a = f.clone();
    a[13] = 0x06;
    if parse_tso_headers(&a, a.len()).is_ok() {
        return TestResult::Fail("ARP frame accepted as IPv4");
    }
    let mut b = f.clone();
    b[14] = 0x44;
    if parse_tso_headers(&b, b.len()).is_ok() {
        return TestResult::Fail("bad IHL accepted");
    }
    let mut u = f.clone();
    u[14 + 9] = 17;
    if parse_tso_headers(&u, u.len()).is_ok() {
        return TestResult::Fail("UDP accepted as TCP");
    }
    let mut d = f.clone();
    d[14 + 20 + 12] = 0x40;
    if parse_tso_headers(&d, d.len()).is_ok() {
        return TestResult::Fail("bad doff accepted");
    }
    // Truncated: IHL 15 (60-byte IP header) but only 60 bytes total.
    let mut tr = alloc::vec![0u8; 60];
    tr[12] = 0x08;
    tr[13] = 0x00;
    tr[14] = 0x4F;
    tr[14 + 9] = 6;
    if parse_tso_headers(&tr, tr.len()).is_ok() {
        return TestResult::Fail("truncated frame accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_tx_tso_parse);

fn smoke_ixgbe_tx_tso_paylen() -> TestResult {
    let d = AdvTxDesc::with_tso(0x1000, 1500, 1460);
    if d.addr != 0x1000 || d.cmd_type_len & ADVTXD_DCMD_TSE == 0 {
        return TestResult::Fail("tso desc missing addr/TSE");
    }
    if d.cmd_type_len & 0xFFFF != 1500 {
        return TestResult::Fail("tso desc DTALEN wrong");
    }
    let want = (1460u32 << ADVTXD_PAYLEN_SHIFT) | ADVTXD_POPTS_IXSM | ADVTXD_POPTS_TXSM;
    if d.olinfo != want {
        return TestResult::Fail("tso desc PAYLEN/POPTS wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_tx_tso_paylen);

fn smoke_ixgbe_tx_plan() -> TestResult {
    use narf_net::{L4CsumKind, TxMeta};
    // Plain frame: no context, no TSE/VLE, PAYLEN = full length.
    let frame = [0u8; 100];
    let (ctxt, desc) = match tx_plan(0x1000, frame.len(), &frame, &TxMeta::plain()) {
        Ok(x) => x,
        Err(_) => return TestResult::Fail("plain plan rejected"),
    };
    if ctxt.is_some()
        || desc.addr != 0x1000
        || desc.cmd_type_len & ADVTXD_DCMD_TSE != 0
        || desc.cmd_type_len & ADVTXD_DCMD_VLE != 0
        || desc.olinfo != (100u32 << 14)
    {
        return TestResult::Fail("plain plan wrong");
    }
    // TSO frame: 2000 bytes, headers 14+20+20, payload 1946.
    let mut tso_frame = alloc::vec![0u8; 2000];
    tso_frame[12] = 0x08;
    tso_frame[13] = 0x00;
    tso_frame[14] = 0x45;
    tso_frame[14 + 9] = 6;
    tso_frame[14 + 20 + 12] = 0x50;
    let (ctxt, desc) = match tx_plan(0x2000, tso_frame.len(), &tso_frame, &TxMeta::with_tso(1460)) {
        Ok(x) => x,
        Err(_) => return TestResult::Fail("tso plan rejected"),
    };
    let c = match ctxt {
        Some(c) => c,
        None => return TestResult::Fail("tso plan missing context"),
    };
    if c.mss_l4len_idx != (20u32 << 8) | (1460u32 << 16) {
        return TestResult::Fail("tso plan context mss/l4len wrong");
    }
    if desc.cmd_type_len & ADVTXD_DCMD_TSE == 0 {
        return TestResult::Fail("tso plan desc missing TSE");
    }
    if desc.olinfo != (1946u32 << ADVTXD_PAYLEN_SHIFT) | ADVTXD_POPTS_IXSM | ADVTXD_POPTS_TXSM {
        return TestResult::Fail("tso plan PAYLEN wrong");
    }
    // VLAN-only: context + VLE, no TSE.
    let mut m = TxMeta::plain();
    m.vlan_tag = Some(0x00AB);
    let (ctxt, desc) = match tx_plan(0x3000, frame.len(), &frame, &m) {
        Ok(x) => x,
        Err(_) => return TestResult::Fail("vlan plan rejected"),
    };
    if ctxt.is_none()
        || desc.cmd_type_len & ADVTXD_DCMD_VLE == 0
        || desc.cmd_type_len & ADVTXD_DCMD_TSE != 0
    {
        return TestResult::Fail("vlan plan wrong");
    }
    // VLAN + TSO: context carries tag, desc carries TSE + VLE.
    let mut mt = TxMeta::with_tso(1460);
    mt.vlan_tag = Some(0x00AB);
    let (ctxt, desc) = match tx_plan(0x4000, tso_frame.len(), &tso_frame, &mt) {
        Ok(x) => x,
        Err(_) => return TestResult::Fail("vlan+tso plan rejected"),
    };
    let c = match ctxt {
        Some(c) => c,
        None => return TestResult::Fail("vlan+tso plan missing context"),
    };
    if c.vlan_macip_lens & 0xFFFF_0000 != 0x00AB_0000 {
        return TestResult::Fail("vlan+tso plan context tag wrong");
    }
    if desc.cmd_type_len & ADVTXD_DCMD_TSE == 0 || desc.cmd_type_len & ADVTXD_DCMD_VLE == 0 {
        return TestResult::Fail("vlan+tso plan desc bits wrong");
    }
    // VLAN + csum without TSO: rejected.
    let mut mc = TxMeta::with_csum(L4CsumKind::Tcp);
    mc.vlan_tag = Some(1);
    if tx_plan(0x5000, frame.len(), &frame, &mc).is_ok() {
        return TestResult::Fail("vlan+csum plan accepted");
    }
    // TSO with mss 0: rejected.
    if tx_plan(0x6000, tso_frame.len(), &tso_frame, &TxMeta::with_tso(0)).is_ok() {
        return TestResult::Fail("tso mss 0 accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_tx_plan);

// ── Ethtool per-queue statistics (QPRC/QPTC, §13i) ──────────────

fn smoke_ixgbe_ethtool_queue_stats() -> TestResult {
    use super::ethtool::{
        qprc_addr, qptc_addr, read_queue_stats, NUM_QUEUE_COUNTERS, QUEUE_COUNTER_STRIDE,
        REG_QPRC_BASE, REG_QPTC_BASE,
    };
    use super::queues::RegBank;
    // Address pins (datasheet §8.2.3.23.74/.78; Linux IXGBE_QPRC/QPTC).
    if NUM_QUEUE_COUNTERS != 16
        || REG_QPRC_BASE != 0x01030
        || REG_QPTC_BASE != 0x06030
        || QUEUE_COUNTER_STRIDE != 0x40
    {
        return TestResult::Fail("queue counter bases wrong");
    }
    if qprc_addr(0) != Some(0x01030)
        || qprc_addr(15) != Some(0x013F0)
        || qprc_addr(16).is_some()
        || qptc_addr(0) != Some(0x06030)
        || qptc_addr(15) != Some(0x063F0)
        || qptc_addr(16).is_some()
    {
        return TestResult::Fail("queue counter addressing wrong");
    }
    let mut bank = FakeBank::new();
    bank.write32(0x01030, 10); // QPRC[0]
    bank.write32(0x01070, 20); // QPRC[1]
    bank.write32(0x010B0, 99); // QPRC[2] — beyond a 2-queue read, must stay unread
    bank.write32(0x013F0, 150); // QPRC[15]
    bank.write32(0x06030, 7); // QPTC[0]
    bank.write32(0x060B0, 27); // QPTC[2]
    bank.write32(0x060F0, 33); // QPTC[3] — beyond a 3-queue read, must stay unread
    let stats = read_queue_stats(&bank, 2, 3);
    if stats.rx_valid != 2 || stats.tx_valid != 3 {
        return TestResult::Fail("queue stats valid counts wrong");
    }
    if stats.rx_packets[0] != 10
        || stats.rx_packets[1] != 20
        || stats.rx_packets[2] != 0
        || stats.tx_packets[0] != 7
        || stats.tx_packets[1] != 0
        || stats.tx_packets[2] != 27
        || stats.tx_packets[3] != 0
    {
        return TestResult::Fail("queue stats interval read wrong");
    }
    // A 64-queue bring-up still reports only the first 16 queues:
    // queues >= 16 have no hardware per-queue counter.
    let wide = read_queue_stats(&bank, 64, 64);
    if wide.rx_valid != 16 || wide.tx_valid != 16 || wide.rx_packets[15] != 150 {
        return TestResult::Fail("queue stats 16-queue cap wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_ethtool_queue_stats);
// ── #1260: multi-queue rings + per-queue vectors ────────────────

fn smoke_ixgbe_multiqueue_register_conversation() -> TestResult {
    use super::queues::{rx_queue_regs, tx_queue_regs, RegBank};
    use super::{
        program_rx_queue, program_tx_queue, RXDCTL_ENABLE, SRRCTL_BSIZE_2K, SRRCTL_DESCTYPE_LEGACY,
        TXDCTL_ENABLE,
    };
    // Fake-bank replay of bring_up_with_config's per-queue
    // programming for TX queues 0..3 + RX queues 0..3 (ring_len 32,
    // distinct ring addresses per queue), plus queue 63
    // (last live queue). Assertions run after ALL programming, so
    // queue 0's block still holding queue 0's values proves
    // queues 1.. did not alias it (stride check with teeth).
    let mut bank = FakeBank::new();
    let ring_len = 32usize;
    for q in 0..4usize {
        let tx_phys: u64 = 0x1_0000_1000 + (q as u64) * 0x1_0000;
        let rx_phys: u64 = 0x1_0000_8000 + (q as u64) * 0x1_0000;
        program_tx_queue(&mut bank, q, tx_phys, ring_len);
        program_rx_queue(&mut bank, q, rx_phys, ring_len);
    }
    program_tx_queue(&mut bank, 63, 0x2_0000_3000, ring_len);
    program_rx_queue(&mut bank, 63, 0x2_0000_9000, ring_len);
    for q in 0..4usize {
        let tx = match tx_queue_regs(q) {
            Some(t) => t,
            None => return TestResult::Fail("tx_queue_regs is None"),
        };
        let rx = match rx_queue_regs(q) {
            Some(r) => r,
            None => return TestResult::Fail("rx_queue_regs is None"),
        };
        let tx_phys: u64 = 0x1_0000_1000 + (q as u64) * 0x1_0000;
        let rx_phys: u64 = 0x1_0000_8000 + (q as u64) * 0x1_0000;
        if bank.read32(tx.tdbal) != tx_phys as u32
            || bank.read32(tx.tdbah) != (tx_phys >> 32) as u32
            || bank.read32(tx.tdlen) != 512
            || bank.read32(tx.tdh) != 0
            || bank.read32(tx.tdt) != 0
            || bank.read32(tx.txdctl) & TXDCTL_ENABLE == 0
        {
            return TestResult::Fail("TX multi-queue conversation wrong");
        }
        if bank.read32(rx.rdbal) != rx_phys as u32
            || bank.read32(rx.rdbah) != (rx_phys >> 32) as u32
            || bank.read32(rx.rdlen) != 512
            || bank.read32(rx.rdh) != 0
            || bank.read32(rx.rdt) != 31
            || bank.read32(rx.srrctl) != (SRRCTL_BSIZE_2K | SRRCTL_DESCTYPE_LEGACY)
            || bank.read32(rx.rxdctl) & RXDCTL_ENABLE == 0
        {
            return TestResult::Fail("RX multi-queue conversation wrong");
        }
    }
    let tx63 = match tx_queue_regs(63) {
        Some(t) => t,
        None => return TestResult::Fail("tx_queue_regs(63) is None"),
    };
    let rx63 = match rx_queue_regs(63) {
        Some(r) => r,
        None => return TestResult::Fail("rx_queue_regs(63) is None"),
    };
    if bank.read32(tx63.tdbal) != 0x0000_3000
        || bank.read32(tx63.tdbah) != 0x2
        || bank.read32(tx63.tdlen) != 512
        || bank.read32(tx63.txdctl) & TXDCTL_ENABLE == 0
    {
        return TestResult::Fail("TX queue-63 conversation wrong");
    }
    if bank.read32(rx63.rdbal) != 0x0000_9000
        || bank.read32(rx63.rdbah) != 0x2
        || bank.read32(rx63.rdlen) != 512
        || bank.read32(rx63.rdt) != 31
        || bank.read32(rx63.rxdctl) & RXDCTL_ENABLE == 0
    {
        return TestResult::Fail("RX queue-63 conversation wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/ixgbe",
    smoke_ixgbe_multiqueue_register_conversation
);

fn smoke_ixgbe_multiqueue_vector_routing_table() -> TestResult {
    use super::queues::{QueueConfig, RegBank, REG_IVAR_BASE, REG_IVAR_MISC};
    use super::route_all_queue_vectors;
    // Asymmetric config (TX 3, RX 5): vectors equal queue indices;
    // queues 3..4 have RX but no TX, so their TX IVAR fields must
    // stay zero while their RX fields route. IVAR[0] covers
    // queues 0..1, IVAR[1] queues 2..3, IVAR[2] queues 4..5.
    let mut bank = FakeBank::new();
    let asym = QueueConfig {
        num_tx: 3,
        num_rx: 5,
        ring_len: 32,
    };
    route_all_queue_vectors(&mut bank, &asym);
    // q0 RX+TX v0 -> 0x8080; q1 RX+TX v1 -> 0x81810000.
    if bank.read32(REG_IVAR_BASE) != 0x8181_8080 {
        return TestResult::Fail("IVAR[0] asymmetric routing wrong");
    }
    // q2 RX+TX v2 -> 0x8282; q3 RX-only v3 -> 0x830000 (TX field 0).
    if bank.read32(REG_IVAR_BASE + 4) != 0x8300_8282 {
        return TestResult::Fail("IVAR[1] asymmetric routing wrong");
    }
    // q4 RX-only v4 -> 0x0084; q5 nothing -> high half 0.
    if bank.read32(REG_IVAR_BASE + 8) != 0x0000_0084 {
        return TestResult::Fail("IVAR[2] asymmetric routing wrong");
    }
    if bank.read32(REG_IVAR_BASE + 12) != 0 {
        return TestResult::Fail("IVAR[3] touched by 5-queue routing");
    }
    if bank.read32(REG_IVAR_MISC) != 0x8000 {
        return TestResult::Fail("IVAR_MISC OTHER routing wrong");
    }
    // Symmetric config (TX 4, RX 4): queue 3 now routes TX too.
    let mut bank2 = FakeBank::new();
    let sym = QueueConfig {
        num_tx: 4,
        num_rx: 4,
        ring_len: 32,
    };
    route_all_queue_vectors(&mut bank2, &sym);
    // q2 0x8282; q3 RX+TX v3 -> 0x83830000.
    if bank2.read32(REG_IVAR_BASE + 4) != 0x8383_8282 {
        return TestResult::Fail("IVAR[1] symmetric routing wrong");
    }
    if bank2.read32(REG_IVAR_MISC) != 0x8000 {
        return TestResult::Fail("IVAR_MISC symmetric routing wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/ixgbe",
    smoke_ixgbe_multiqueue_vector_routing_table
);

fn smoke_ixgbe_multiqueue_config() -> TestResult {
    use super::queues::{QueueConfig, QueueError};
    let ok = [
        QueueConfig {
            num_tx: 4,
            num_rx: 4,
            ring_len: 64,
        },
        QueueConfig {
            num_tx: 64,
            num_rx: 64,
            ring_len: 4096,
        },
        QueueConfig {
            num_tx: 64,
            num_rx: 1,
            ring_len: 32,
        },
        QueueConfig {
            num_tx: 1,
            num_rx: 64,
            ring_len: 32,
        },
    ];
    for cfg in ok {
        if cfg.validate().is_err() {
            return TestResult::Fail("valid multi-queue config rejected");
        }
    }
    let bad_len = QueueConfig {
        num_tx: 2,
        num_rx: 2,
        ring_len: 8192,
    };
    if bad_len.validate() != Err(QueueError::BadRingLen) {
        return TestResult::Fail("8192-entry ring accepted");
    }
    let zero_len = QueueConfig {
        num_tx: 2,
        num_rx: 2,
        ring_len: 0,
    };
    if zero_len.validate() != Err(QueueError::BadRingLen) {
        return TestResult::Fail("0-entry ring accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_multiqueue_config);

fn smoke_ixgbe_queue_vector_for() -> TestResult {
    use super::queue_vector_for;
    use super::queues::QueueConfig;
    let single = QueueConfig::single();
    if queue_vector_for(&single, 0) != Some(0) || queue_vector_for(&single, 1).is_some() {
        return TestResult::Fail("single-queue vector mapping wrong");
    }
    let asym = QueueConfig {
        num_tx: 3,
        num_rx: 5,
        ring_len: 32,
    };
    if queue_vector_for(&asym, 0) != Some(0)
        || queue_vector_for(&asym, 2) != Some(2)
        || queue_vector_for(&asym, 3) != Some(3)
        || queue_vector_for(&asym, 4) != Some(4)
        || queue_vector_for(&asym, 5).is_some()
    {
        return TestResult::Fail("asymmetric vector mapping wrong");
    }
    let full = QueueConfig {
        num_tx: 64,
        num_rx: 64,
        ring_len: 32,
    };
    if queue_vector_for(&full, 63) != Some(63) || queue_vector_for(&full, 64).is_some() {
        return TestResult::Fail("64-queue vector mapping wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_queue_vector_for);

// ── VMDq / SR-IOV fixtures (issue #1261) ───────────────────────────

fn smoke_ixgbe_vmdq_pool_mapping() -> TestResult {
    use super::vmdq::{mtqc_vt_word, pool_for_vf, pool_queues, primary_rar, qde_word, vt_ctl_word};
    if pool_for_vf(0) != Some(1) || pool_for_vf(62) != Some(63) || pool_for_vf(63).is_some() {
        return TestResult::Fail("pool_for_vf mapping wrong (PF pool 0, VF i -> i+1)");
    }
    if pool_queues(0) != Some((0, 1))
        || pool_queues(63) != Some((126, 127))
        || pool_queues(64).is_some()
    {
        return TestResult::Fail("pool_queues mapping wrong");
    }
    if primary_rar(0) != 1 || primary_rar(62) != 63 {
        return TestResult::Fail("primary_rar mapping wrong");
    }
    if qde_word(4, true, false) != 0x1_0401 || qde_word(5, false, true) != 0x1_0502 {
        return TestResult::Fail("qde_word packing wrong");
    }
    if vt_ctl_word(3, true) != 0x4000_0180 || vt_ctl_word(0, false) != 0 {
        return TestResult::Fail("vt_ctl_word packing wrong");
    }
    if mtqc_vt_word() != 0x6 {
        return TestResult::Fail("mtqc_vt_word wrong (VT_ENA | 64VF)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vmdq_pool_mapping);

fn smoke_ixgbe_vmdq_enable_conversation() -> TestResult {
    use super::queues::RegBank;
    use super::vmdq::{
        enable_virtualization, VmdqConfig, REG_MRQC, REG_MTQC, REG_PFDTXGSWC, REG_RTTDCS,
        REG_VT_CTL,
    };
    let mut bank = FakeBank::new();
    bank.write32(REG_RTTDCS, 0x1234_0000);
    bank.write32(REG_MRQC, 0xFFFF_0000);
    bank.write32(REG_VT_CTL, 0x0000_1F80);
    if enable_virtualization(&mut bank, &VmdqConfig::standard()).is_err() {
        return TestResult::Fail("enable_virtualization failed on a valid config");
    }
    // Arbiter disabled for the MTQC write, then re-enabled with the
    // other RTTDCS bits preserved.
    if bank.read32(REG_RTTDCS) != 0x1234_0000 {
        return TestResult::Fail("RTTDCS arbiter not restored after MTQC");
    }
    if bank.read32(REG_MTQC) != 0x6 {
        return TestResult::Fail("MTQC VT word wrong");
    }
    // MRQE field replaced, upper bits preserved.
    if bank.read32(REG_MRQC) != 0xFFFF_0008 {
        return TestResult::Fail("MRQC VMDQEN word wrong");
    }
    // Pool field replaced (was pool 63), replication set.
    if bank.read32(REG_VT_CTL) != 0x4000_0000 {
        return TestResult::Fail("VT_CTL default-pool/replication word wrong");
    }
    if bank.read32(REG_PFDTXGSWC) != 0x1 {
        return TestResult::Fail("PFDTXGSWC VEB bit not set");
    }
    if VmdqConfig::new(64, true).is_ok() {
        return TestResult::Fail("VmdqConfig accepted pool 64");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vmdq_enable_conversation);

fn smoke_ixgbe_vmdq_mpsar_rar() -> TestResult {
    use super::queues::RegBank;
    use super::vmdq::{
        assign_rar_pool, clear_rar, clear_rar_pool, mpsar_hi, mpsar_lo, program_rar, rah, ral,
        rar_enabled, rar_has_pool, read_rar, RAH_AV,
    };
    let mut bank = FakeBank::new();
    if assign_rar_pool(&mut bank, 5, 40).is_err() || assign_rar_pool(&mut bank, 5, 3).is_err() {
        return TestResult::Fail("assign_rar_pool failed");
    }
    if bank.read32(mpsar_hi(5)) != 0x100 || bank.read32(mpsar_lo(5)) != 0x8 {
        return TestResult::Fail("MPSAR pool bits wrong (40 -> HI bit 8, 3 -> LO bit 3)");
    }
    if !rar_has_pool(&bank, 5, 40) || rar_has_pool(&bank, 5, 4) {
        return TestResult::Fail("rar_has_pool wrong");
    }
    if clear_rar_pool(&mut bank, 5, 40).is_err() || bank.read32(mpsar_hi(5)) != 0 {
        return TestResult::Fail("clear_rar_pool did not clear HI bit");
    }
    if bank.read32(mpsar_lo(5)) != 0x8 {
        return TestResult::Fail("clear_rar_pool disturbed the LO word");
    }
    let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    if program_rar(&mut bank, 1, &mac, 1, true).is_err() {
        return TestResult::Fail("program_rar failed");
    }
    if bank.read32(ral(1)) != 0x3322_1102 || bank.read32(rah(1)) != (RAH_AV | 0x5544) {
        return TestResult::Fail("RAR words wrong (RAL LE bytes, RAH AV | MAC hi)");
    }
    if bank.read32(mpsar_lo(1)) != 0x2 {
        return TestResult::Fail("program_rar did not select the pool first");
    }
    if !rar_enabled(&bank, 1) || read_rar(&bank, 1) != (mac, true) {
        return TestResult::Fail("RAR read-back wrong");
    }
    if clear_rar(&mut bank, 1).is_err() || rar_enabled(&bank, 1) {
        return TestResult::Fail("clear_rar did not drop AV");
    }
    if read_rar(&bank, 1) != (mac, false) {
        return TestResult::Fail("clear_rar disturbed MAC bytes");
    }
    if assign_rar_pool(&mut bank, 128, 0).is_ok()
        || program_rar(&mut bank, 0, &mac, 64, true).is_ok()
    {
        return TestResult::Fail("out-of-range RAR/pool accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vmdq_mpsar_rar);

fn smoke_ixgbe_vmdq_pool_vlan() -> TestResult {
    use super::queues::RegBank;
    use super::vlan::REG_VFTA_BASE;
    use super::vmdq::{clear_pool_vlan, find_vlvf_slot, set_pool_vlan, vlvf, vlvfb, VLVF_VIEN};
    let mut bank = FakeBank::new();
    if set_pool_vlan(&mut bank, 100, 5).is_err() {
        return TestResult::Fail("set_pool_vlan failed");
    }
    // Highest empty slot wins (Linux scans 63..1).
    if find_vlvf_slot(&bank, 100) != Some(63) || bank.read32(vlvf(63)) != (VLVF_VIEN | 100) {
        return TestResult::Fail("VLVF slot allocation wrong");
    }
    if bank.read32(vlvfb(126)) != 0x20 {
        return TestResult::Fail("VLVFB pool-5 bit wrong");
    }
    if bank.read32(REG_VFTA_BASE + 4 * 3) != 0x10 {
        return TestResult::Fail("VFTA bit for VID 100 not set");
    }
    if set_pool_vlan(&mut bank, 100, 7).is_err() || bank.read32(vlvfb(126)) != 0xA0 {
        return TestResult::Fail("second pool did not join the same VLVF slot");
    }
    if clear_pool_vlan(&mut bank, 100, 5).is_err() || bank.read32(vlvfb(126)) != 0x80 {
        return TestResult::Fail("clear_pool_vlan did not drop pool 5");
    }
    if bank.read32(vlvf(63)) != (VLVF_VIEN | 100) {
        return TestResult::Fail("VLVF slot disabled while pool 7 remains");
    }
    if clear_pool_vlan(&mut bank, 100, 7).is_err()
        || bank.read32(vlvfb(126)) != 0
        || bank.read32(vlvf(63)) != 0
    {
        return TestResult::Fail("last pool clear did not disable the slot");
    }
    // VFTA is deliberately untouched by clears (PF filter state).
    if bank.read32(REG_VFTA_BASE + 4 * 3) != 0x10 {
        return TestResult::Fail("clear_pool_vlan touched VFTA");
    }
    if clear_pool_vlan(&mut bank, 300, 5).is_ok() {
        return TestResult::Fail("clear of an absent VLAN succeeded");
    }
    // VLAN 0 always maps to slot 0.
    if set_pool_vlan(&mut bank, 0, 2).is_err()
        || bank.read32(vlvf(0)) != VLVF_VIEN
        || bank.read32(vlvfb(0)) != 0x4
    {
        return TestResult::Fail("VLAN 0 did not map to slot 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vmdq_pool_vlan);

fn smoke_ixgbe_vmdq_vf_state_regs() -> TestResult {
    use super::queues::RegBank;
    use super::vmdq::{
        clear_vf_reset_event, clear_vmvir, pvftdwbah, pvftdwbal, qde_word, reset_vf_tx_addrs,
        set_pool_queue_drop, set_spoof_count, set_vf_rx_tx, set_vmolr, set_vmvir, vf_reset_pending,
        vflre, vflrec, vfre, vfte, vmecm, vmolr, vmvir, REG_QDE, VMOLR_AUPE, VMOLR_BAM,
    };
    let mut bank = FakeBank::new();
    if set_vmolr(&mut bank, 3, true).is_err() || bank.read32(vmolr(3)) != (VMOLR_BAM | VMOLR_AUPE) {
        return TestResult::Fail("VMOLR BAM|AUPE wrong");
    }
    if set_vmolr(&mut bank, 3, false).is_err() || bank.read32(vmolr(3)) != VMOLR_BAM {
        return TestResult::Fail("VMOLR AUPE clear wrong");
    }
    if set_vmvir(&mut bank, 2, 100, 5).is_err()
        || bank.read32(vmvir(2)) != (100 | (5 << 13) | 0x4000_0000)
    {
        return TestResult::Fail("VMVIR word wrong");
    }
    if clear_vmvir(&mut bank, 2).is_err() || bank.read32(vmvir(2)) != 0 {
        return TestResult::Fail("VMVIR clear wrong");
    }
    if set_vf_rx_tx(&mut bank, 40, true).is_err()
        || bank.read32(vfre(1)) != 0x100
        || bank.read32(vfte(1)) != 0x100
    {
        return TestResult::Fail("VFRE/VFTE enable wrong (VF 40 -> word 1 bit 8)");
    }
    if set_vf_rx_tx(&mut bank, 40, false).is_err()
        || bank.read32(vfre(1)) != 0
        || bank.read32(vfte(1)) != 0
    {
        return TestResult::Fail("VFRE/VFTE disable wrong");
    }
    // QDE is a single register: the pool call ends on the last queue.
    if set_pool_queue_drop(&mut bank, 2, true, false).is_err()
        || bank.read32(REG_QDE) != qde_word(5, true, false)
    {
        return TestResult::Fail("QDE pool programming wrong");
    }
    if set_spoof_count(&mut bank, 40, true).is_err() || bank.read32(vmecm(1)) != 0x100 {
        return TestResult::Fail("VMECM spoof-count bit wrong");
    }
    bank.write32(pvftdwbal(4), 0xDEAD);
    bank.write32(pvftdwbah(5), 0xBEEF);
    if reset_vf_tx_addrs(&mut bank, 2).is_err()
        || bank.read32(pvftdwbal(4)) != 0
        || bank.read32(pvftdwbah(5)) != 0
    {
        return TestResult::Fail("TX write-back reset wrong");
    }
    bank.write32(vflre(40), 0x100);
    if !vf_reset_pending(&bank, 40) {
        return TestResult::Fail("VFLRE reset event not seen");
    }
    if clear_vf_reset_event(&mut bank, 40).is_err() || bank.read32(vflrec(40)) != 0x100 {
        return TestResult::Fail("VFLREC clear word wrong");
    }
    if set_vmolr(&mut bank, 63, true).is_ok() || set_vf_rx_tx(&mut bank, 63, true).is_ok() {
        return TestResult::Fail("VF 63 accepted (max is 62)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vmdq_vf_state_regs);

fn smoke_ixgbe_vmdq_mailbox_transport() -> TestResult {
    use super::queues::RegBank;
    use super::vmdq::{
        mailbox_clear, mailbox_has_ack, mailbox_has_msg, mailbox_lock, mailbox_read, mailbox_write,
        mbvficr, pfmailbox, pfmbmem, MBVFICR_VFACK_VF1, MBVFICR_VFREQ_VF1, PFMAILBOX_ACK,
        PFMAILBOX_PFU, PFMAILBOX_STS,
    };
    let mut bank = FakeBank::new();
    // Lock: PFU written, echoed back, accepted.
    if mailbox_lock(&mut bank, 1).is_err() || bank.read32(pfmailbox(1)) != PFMAILBOX_PFU {
        return TestResult::Fail("mailbox_lock did not take PFU");
    }
    let msg = [0x01, 0x1122_3344, 0x5566_7788, 0x99AA_BBCC];
    if mailbox_write(&mut bank, 1, &msg).is_err() {
        return TestResult::Fail("mailbox_write failed");
    }
    if bank.read32(pfmbmem(1)) != 0x01
        || bank.read32(pfmbmem(1) + 4) != 0x1122_3344
        || bank.read32(pfmbmem(1) + 12) != 0x99AA_BBCC
        || bank.read32(pfmailbox(1)) != PFMAILBOX_STS
    {
        return TestResult::Fail("mailbox_write words or STS wrong");
    }
    // Simulate the VF side: set request + ack bits in MBVFICR.
    bank.write32(mbvficr(1), MBVFICR_VFREQ_VF1 << 1 | MBVFICR_VFACK_VF1 << 1);
    if !mailbox_has_msg(&bank, 1) || !mailbox_has_ack(&bank, 1) {
        return TestResult::Fail("MBVFICR request/ack bits not seen");
    }
    if mailbox_has_msg(&bank, 2) || mailbox_has_ack(&bank, 2) {
        return TestResult::Fail("MBVFICR bits leaked to VF 2");
    }
    let mut out = [0u32; 4];
    if mailbox_read(&mut bank, 1, &mut out).is_err() || out != msg {
        return TestResult::Fail("mailbox_read words wrong");
    }
    if bank.read32(pfmailbox(1)) != PFMAILBOX_ACK {
        return TestResult::Fail("mailbox_read did not leave ACK");
    }
    if mailbox_clear(&mut bank, 1).is_err() || bank.read32(pfmbmem(1) + 4) != 0 {
        return TestResult::Fail("mailbox_clear did not zero memory");
    }
    if mailbox_lock(&mut bank, 63).is_ok() {
        return TestResult::Fail("mailbox_lock accepted VF 63");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vmdq_mailbox_transport);

fn vmdq_msg(word0: u32, word1: u32) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[0] = word0;
    m[1] = word1;
    m
}

fn smoke_ixgbe_vmdq_dispatch_reset() -> TestResult {
    use super::queues::RegBank;
    use super::vmdq::{
        dispatch_vf_message, pfmbmem, rah, ral, vmolr, DispatchOutcome, VfTable, VF_RESET,
        VMOLR_AUPE, VMOLR_BAM, VT_MSGTYPE_ACK, VT_MSGTYPE_NACK,
    };
    let mut bank = FakeBank::new();
    let mut table = VfTable::new();
    // No MAC, no admin pin: NACK reply, defaults programmed.
    let msg = vmdq_msg(VF_RESET, 0);
    match dispatch_vf_message(&mut bank, &mut table, 0, &msg) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("RESET dispatch did not reply"),
    }
    if bank.read32(pfmbmem(0)) != (VF_RESET | VT_MSGTYPE_NACK)
        || bank.read32(pfmbmem(0) + 4) != 0
        || bank.read32(pfmbmem(0) + 12) != 0
    {
        return TestResult::Fail("RESET NACK reply words wrong");
    }
    if bank.read32(vmolr(0)) != (VMOLR_BAM | VMOLR_AUPE) {
        return TestResult::Fail("RESET VMOLR default wrong (BAM|AUPE, no PF VLAN)");
    }
    if !table.vfs[0].clear_to_send || table.vfs[0].api != 0 {
        return TestResult::Fail("RESET did not set clear_to_send / API 1.0");
    }
    // Pinned MAC: ACK reply with the MAC, RAR slot programmed.
    table.vfs[0].mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    table.vfs[0].mac_set = true;
    table.vfs[0].pf_set_mac = true;
    match dispatch_vf_message(&mut bank, &mut table, 0, &msg) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("RESET with pinned MAC did not reply"),
    }
    if bank.read32(pfmbmem(0)) != (VF_RESET | VT_MSGTYPE_ACK)
        || bank.read32(pfmbmem(0) + 4) != 0x02
        || bank.read32(pfmbmem(0) + 8) != 0x0100
    {
        return TestResult::Fail("RESET ACK reply MAC words wrong");
    }
    if bank.read32(ral(1)) != 0x02 || bank.read32(rah(1)) != (0x8000_0000 | 0x0100) {
        return TestResult::Fail("RESET did not program primary RAR slot 1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vmdq_dispatch_reset);

fn smoke_ixgbe_vmdq_dispatch_messages() -> TestResult {
    use super::queues::RegBank;
    use super::vmdq::{
        dispatch_vf_message, pfmbmem, rah, ral, vlvf, vlvfb, DispatchOutcome, VfTable, REG_MAXFRS,
        VF_API_NEGOTIATE, VF_GET_QUEUES, VF_RESET, VF_SET_LPE, VF_SET_MACVLAN, VF_SET_MAC_ADDR,
        VF_SET_MULTICAST, VF_SET_VLAN, VLVF_VIEN, VT_MSGTYPE_ACK, VT_MSGTYPE_CTS, VT_MSGTYPE_NACK,
    };
    let mut bank = FakeBank::new();
    let mut table = VfTable::new();
    // SET_MAC, valid unicast: ACK|CTS, RAR programmed, state stored.
    let mac_lo = 0x3322_1102u32;
    let mac_hi = 0x5544u32;
    let mut msg = vmdq_msg(VF_SET_MAC_ADDR, mac_lo);
    msg[2] = mac_hi;
    match dispatch_vf_message(&mut bank, &mut table, 0, &msg) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_MAC dispatch did not reply"),
    }
    if bank.read32(pfmbmem(0)) != (VF_SET_MAC_ADDR | VT_MSGTYPE_ACK | VT_MSGTYPE_CTS) {
        return TestResult::Fail("SET_MAC reply word0 wrong");
    }
    if bank.read32(ral(1)) != mac_lo || bank.read32(rah(1)) != (0x8000_0000 | mac_hi) {
        return TestResult::Fail("SET_MAC did not program RAR slot 1");
    }
    if !table.vfs[0].mac_set || table.vfs[0].mac != [0x02, 0x11, 0x22, 0x33, 0x44, 0x55] {
        return TestResult::Fail("SET_MAC state wrong");
    }
    // SET_MAC, multicast address: NACK, RAR untouched.
    let mut bad = vmdq_msg(VF_SET_MAC_ADDR, 0x3322_1103);
    bad[2] = mac_hi;
    match dispatch_vf_message(&mut bank, &mut table, 1, &bad) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("bad SET_MAC dispatch did not reply"),
    }
    if bank.read32(pfmbmem(1)) != (VF_SET_MAC_ADDR | VT_MSGTYPE_NACK | VT_MSGTYPE_CTS) {
        return TestResult::Fail("bad SET_MAC reply not NACK|CTS");
    }
    if bank.read32(rah(2)) & 0x8000_0000 != 0 {
        return TestResult::Fail("bad SET_MAC programmed a RAR");
    }
    // API negotiate: 1.1 accepted, 1.5 refused (Linux excludes it).
    let mut table2 = VfTable::new();
    match dispatch_vf_message(&mut bank, &mut table2, 0, &vmdq_msg(VF_API_NEGOTIATE, 2)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("API negotiate dispatch did not reply"),
    }
    if table2.vfs[0].api != 2 || bank.read32(pfmbmem(0)) & VT_MSGTYPE_ACK == 0 {
        return TestResult::Fail("API 1.1 not accepted");
    }
    let mut table3 = VfTable::new();
    match dispatch_vf_message(&mut bank, &mut table3, 0, &vmdq_msg(VF_API_NEGOTIATE, 6)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("API 1.5 dispatch did not reply"),
    }
    if table3.vfs[0].api != 0 || bank.read32(pfmbmem(0)) & VT_MSGTYPE_NACK == 0 {
        return TestResult::Fail("API 1.5 not refused");
    }
    // GET_QUEUES: refused on API 1.0, accepted after 1.1 negotiate.
    match dispatch_vf_message(&mut bank, &mut table3, 0, &vmdq_msg(VF_GET_QUEUES, 0)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("GET_QUEUES dispatch did not reply"),
    }
    if bank.read32(pfmbmem(0)) & VT_MSGTYPE_NACK == 0 {
        return TestResult::Fail("GET_QUEUES not refused on API 1.0");
    }
    match dispatch_vf_message(&mut bank, &mut table2, 0, &vmdq_msg(VF_GET_QUEUES, 0)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("GET_QUEUES (1.1) dispatch did not reply"),
    }
    if bank.read32(pfmbmem(0)) != (VF_GET_QUEUES | VT_MSGTYPE_ACK | VT_MSGTYPE_CTS)
        || bank.read32(pfmbmem(0) + 4) != 2
        || bank.read32(pfmbmem(0) + 8) != 2
        || bank.read32(pfmbmem(0) + 12) != 0
        || bank.read32(pfmbmem(0) + 16) != 0
    {
        return TestResult::Fail("GET_QUEUES reply words wrong (2, 2, 0, 0)");
    }
    // SET_VLAN add + remove, then remove-absent NACK.
    let add = vmdq_msg(VF_SET_VLAN | (1 << 16), 200);
    match dispatch_vf_message(&mut bank, &mut table2, 0, &add) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_VLAN add did not reply"),
    }
    if bank.read32(vlvf(63)) != (VLVF_VIEN | 200) || bank.read32(vlvfb(126)) & 0x2 == 0 {
        return TestResult::Fail("SET_VLAN add did not program pool 1");
    }
    let rem = vmdq_msg(VF_SET_VLAN, 200);
    match dispatch_vf_message(&mut bank, &mut table2, 0, &rem) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_VLAN remove did not reply"),
    }
    if bank.read32(vlvf(63)) != 0 || bank.read32(vlvfb(126)) != 0 {
        return TestResult::Fail("SET_VLAN remove did not clear the slot");
    }
    match dispatch_vf_message(&mut bank, &mut table2, 0, &vmdq_msg(VF_SET_VLAN, 300)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_VLAN absent-remove did not reply"),
    }
    if bank.read32(pfmbmem(0)) & VT_MSGTYPE_NACK == 0 {
        return TestResult::Fail("SET_VLAN absent-remove not NACKed");
    }
    // SET_LPE: in range bumps MAXFRS, out of range NACKs.
    match dispatch_vf_message(&mut bank, &mut table2, 0, &vmdq_msg(VF_SET_LPE, 9000)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_LPE did not reply"),
    }
    if bank.read32(REG_MAXFRS) != (9000 << 16) {
        return TestResult::Fail("SET_LPE MAXFRS bump wrong");
    }
    match dispatch_vf_message(&mut bank, &mut table2, 0, &vmdq_msg(VF_SET_LPE, 20000)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_LPE range dispatch did not reply"),
    }
    if bank.read32(pfmbmem(0)) & VT_MSGTYPE_NACK == 0 || bank.read32(REG_MAXFRS) != (9000 << 16) {
        return TestResult::Fail("SET_LPE out-of-range not NACKed or moved MAXFRS");
    }
    // SET_MACVLAN index 1 deletes the VF's extra filters, primary kept.
    let mut bank2 = FakeBank::new();
    let mut table4 = VfTable::new();
    {
        use super::vmdq::{mpsar_lo, program_rar};
        let extra = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        if program_rar(&mut bank2, 10, &extra, 1, true).is_err() {
            return TestResult::Fail("MACVLAN fixture setup failed");
        }
        if program_rar(&mut bank2, 1, &[0x02, 0, 0, 0, 0, 0x01], 1, true).is_err() {
            return TestResult::Fail("MACVLAN primary fixture setup failed");
        }
        if bank2.read32(mpsar_lo(10)) != 0x2 {
            return TestResult::Fail("MACVLAN fixture MPSAR wrong");
        }
    }
    match dispatch_vf_message(
        &mut bank2,
        &mut table4,
        0,
        &vmdq_msg(VF_SET_MACVLAN | (1 << 16), 0),
    ) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_MACVLAN delete did not reply"),
    }
    if bank2.read32(rah(10)) & 0x8000_0000 != 0 {
        return TestResult::Fail("SET_MACVLAN delete kept the extra filter");
    }
    if bank2.read32(rah(1)) & 0x8000_0000 == 0 {
        return TestResult::Fail("SET_MACVLAN delete removed the primary MAC");
    }
    // SET_MACVLAN index 5: success no-op (Linux add path commented out).
    match dispatch_vf_message(
        &mut bank2,
        &mut table4,
        0,
        &vmdq_msg(VF_SET_MACVLAN | (5 << 16), 0),
    ) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_MACVLAN add did not reply"),
    }
    if bank2.read32(pfmbmem(0)) & VT_MSGTYPE_ACK == 0 {
        return TestResult::Fail("SET_MACVLAN add not ACKed");
    }
    // Already-ACKed message: ignored, mailbox untouched.
    let mut bank3 = FakeBank::new();
    let mut table5 = VfTable::new();
    let acked = vmdq_msg(VF_SET_MAC_ADDR | VT_MSGTYPE_ACK, 0);
    match dispatch_vf_message(&mut bank3, &mut table5, 0, &acked) {
        Ok(DispatchOutcome::Ignored) => {}
        _ => return TestResult::Fail("already-ACKed message not ignored"),
    }
    if bank3.read32(pfmbmem(0)) != 0 {
        return TestResult::Fail("ignored message wrote to the mailbox");
    }
    // Unknown type + SET_MULTICAST: NACK|CTS.
    match dispatch_vf_message(&mut bank3, &mut table5, 0, &vmdq_msg(0x77, 0)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("unknown message did not reply"),
    }
    if bank3.read32(pfmbmem(0)) != (0x77 | VT_MSGTYPE_NACK | VT_MSGTYPE_CTS) {
        return TestResult::Fail("unknown message reply wrong");
    }
    match dispatch_vf_message(&mut bank3, &mut table5, 0, &vmdq_msg(VF_SET_MULTICAST, 0)) {
        Ok(DispatchOutcome::Replied) => {}
        _ => return TestResult::Fail("SET_MULTICAST did not reply"),
    }
    if bank3.read32(pfmbmem(0)) & VT_MSGTYPE_NACK == 0 {
        return TestResult::Fail("SET_MULTICAST not NACKed");
    }
    // Out-of-range VF: error before any bank access.
    if dispatch_vf_message(&mut bank3, &mut table5, 63, &vmdq_msg(VF_RESET, 0)).is_ok() {
        return TestResult::Fail("VF 63 dispatch accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/ixgbe", smoke_ixgbe_vmdq_dispatch_messages);
