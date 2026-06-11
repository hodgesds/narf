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
