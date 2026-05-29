//! rtlwifi smoke tests.
//!
//! All smokes are pure-data (no live MMIO): PCI-ID table coverage, EFUSE
//! descriptor layout, TX/RX descriptor field extraction, firmware blob-name
//! resolution, per-chip register-bank size table.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::efuse::{mac_is_valid, EfuseError};
use super::fw::fw_name_for;
use super::pci::{name_for, register_pci_driver};
use super::regs::*;
use super::rtl8188ee::{RxDesc, TxDesc};

// ── 1. PCI-ID table coverage (≥8 IDs) ────────────────────────────────────

fn smoke_rtlwifi_pci_id_table_coverage() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();

    // The spec requires ≥8 distinct IDs be registered.
    let count = registered
        .iter()
        .filter(|m| {
            matches!(m.kind, MatchKind::VendorDevice { vendor: REALTEK_VENDOR, .. })
        })
        .count();

    if count < 8 {
        return TestResult::Fail("rtlwifi: fewer than 8 PCI device IDs registered");
    }

    // Spot-check the required IDs from the spec.
    let required = [
        RTL_DEV_8188EE,
        RTL_DEV_8192CE,
        RTL_DEV_8192DE,
        RTL_DEV_8192EE,
        RTL_DEV_8723AE,
        RTL_DEV_8723BE,
        RTL_DEV_8821AE,
        RTL_DEV_8822BE,
    ];
    for did in required {
        let found = registered.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice { vendor: REALTEK_VENDOR, device } if device == did
            )
        });
        if !found {
            return TestResult::Fail("rtlwifi: required device ID missing from table");
        }
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_pci_id_table_coverage);

// ── 2. EFUSE descriptor decoder ───────────────────────────────────────────

fn smoke_rtlwifi_efuse_descriptor_layout() -> TestResult {
    // VALID must be bit 31.
    if EFUSE_CTRL_VALID != 1u32 << 31 {
        return TestResult::Fail("EFUSE_CTRL_VALID not at bit 31");
    }
    // Address field shifts at bit 8 for the 8188EE/8192EE family.
    if EFUSE_CTRL_ADDR_SHIFT != 8 {
        return TestResult::Fail("EFUSE_CTRL_ADDR_SHIFT is not 8");
    }
    // Data byte in low 8 bits.
    if EFUSE_CTRL_DATA_MASK != 0x0000_00FF {
        return TestResult::Fail("EFUSE_CTRL_DATA_MASK is not 0xFF");
    }
    // LDOE25 occupies bits [31:28] = 0x03 << 28.
    if EFUSE_TEST_LDOE25_EN != 0x03 << 28 {
        return TestResult::Fail("EFUSE_TEST_LDOE25_EN wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_efuse_descriptor_layout);

// ── 3. TX descriptor layout for BE queue ─────────────────────────────────

fn smoke_rtlwifi_tx_desc_be_queue() -> TestResult {
    // Confirm TX descriptor is exactly 64 bytes (16 dwords).
    if core::mem::size_of::<TxDesc>() != TX_DESC_SIZE {
        return TestResult::Fail("TxDesc size != TX_DESC_SIZE");
    }
    // Build a minimal TX descriptor for a BE-queue frame.
    let mut desc = TxDesc::default();
    desc.set_pkt_size(1500);
    desc.set_single_mpdu();
    desc.set_queuesel(QSLT_BE);
    desc.set_buf_addr(0x1000_0000);
    desc.set_buf_size(1500);
    desc.set_own(true);

    // OWN must be set in DW0 bit 31.
    if desc.dwords[0] & (1u32 << 31) == 0 {
        return TestResult::Fail("TX OWN bit not set after set_own(true)");
    }
    // QSLT_BE = 0x00 — queue field bits[12:8] of DW1 should be 0.
    if (desc.dwords[1] >> 8) & 0x1F != QSLT_BE as u32 {
        return TestResult::Fail("TX queuesel not QSLT_BE");
    }
    // pkt_size should sit in low 16 bits of DW0.
    if desc.dwords[0] & 0xFFFF != 1500 {
        return TestResult::Fail("TX pkt_size not in low 16 bits of DW0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_tx_desc_be_queue);

// ── 4. RX descriptor layout ───────────────────────────────────────────────

fn smoke_rtlwifi_rx_desc_layout() -> TestResult {
    // Confirm RX descriptor is exactly 32 bytes (8 dwords).
    if core::mem::size_of::<RxDesc>() != RX_DESC_SIZE {
        return TestResult::Fail("RxDesc size != RX_DESC_SIZE");
    }
    // Synthesize a completed (driver-owned) RX descriptor.
    let mut desc = RxDesc::default();
    // Simulate hardware completing a 200-byte MPDU: clear OWN, set length.
    desc.dwords[0] = 200u32; // OWN=0, length=200
    if desc.is_hw_owned() {
        return TestResult::Fail("RxDesc with OWN=0 reports hw-owned");
    }
    if desc.pkt_len() != 200 {
        return TestResult::Fail("RxDesc pkt_len() wrong");
    }
    // Reclaim: should set OWN and write buf_addr into DW6.
    desc.reclaim(0x2000_0000);
    if !desc.is_hw_owned() {
        return TestResult::Fail("RxDesc not hw-owned after reclaim");
    }
    if desc.dwords[6] != 0x2000_0000 {
        return TestResult::Fail("RxDesc buf_addr not written to DW6 on reclaim");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_rx_desc_layout);

// ── 5. Firmware blob-name resolution by chip ─────────────────────────────

fn smoke_rtlwifi_fw_blob_name_by_chip() -> TestResult {
    let cases: &[(u16, &str)] = &[
        (RTL_DEV_8188EE, "rtlwifi/rtl8188eefw.bin"),
        (RTL_DEV_8192CE, "rtlwifi/rtl8192cfw.bin"),
        (RTL_DEV_8192CE_ALT, "rtlwifi/rtl8192cfw.bin"),
        (RTL_DEV_8192DE, "rtlwifi/rtl8192defw.bin"),
        (RTL_DEV_8192EE, "rtlwifi/rtl8192eefw.bin"),
        (RTL_DEV_8723AE, "rtlwifi/rtl8723aefw.bin"),
        (RTL_DEV_8723BE, "rtlwifi/rtl8723befw.bin"),
        (RTL_DEV_8821AE, "rtlwifi/rtl8821aefw.bin"),
        (RTL_DEV_8822BE, "rtlwifi/rtl8822befw.bin"),
    ];
    for &(did, expected) in cases {
        match fw_name_for(did) {
            None => return TestResult::Fail("fw_name_for: unexpected None"),
            Some(got) if got != expected => {
                return TestResult::Fail("fw_name_for: wrong blob name");
            }
            _ => {}
        }
    }
    // Unknown device should return None.
    if fw_name_for(0xFFFF).is_some() {
        return TestResult::Fail("fw_name_for(0xFFFF) should return None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_fw_blob_name_by_chip);

// ── 6. Per-chip register-bank size table ─────────────────────────────────

fn smoke_rtlwifi_per_chip_mmio_size_table() -> TestResult {
    // Every chip in the family uses a 16 KiB (0x4000) BAR0 window.
    // Verify that the per-chip constants match.
    let sizes: &[(u16, usize)] = &[
        (RTL_DEV_8188EE, super::rtl8188ee::MMIO_SIZE),
        (RTL_DEV_8192CE, super::rtl8192ce::MMIO_SIZE),
        (RTL_DEV_8192EE, super::rtl8192ee::MMIO_SIZE),
        (RTL_DEV_8723BE, super::rtl8723be::MMIO_SIZE),
        (RTL_DEV_8821AE, super::rtl8821ae::MMIO_SIZE),
        (RTL_DEV_8822BE, super::rtl8822be::MMIO_SIZE),
    ];
    for &(did, sz) in sizes {
        if sz != 0x4000 {
            return TestResult::Fail("per-chip MMIO_SIZE is not 0x4000");
        }
        let _ = did; // suppress unused warning
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_per_chip_mmio_size_table);

// ── 7. MAC validity classifier ────────────────────────────────────────────

fn smoke_rtlwifi_mac_is_valid() -> TestResult {
    if mac_is_valid([0u8; 6]) {
        return TestResult::Fail("all-zero MAC reported valid");
    }
    if mac_is_valid([0xFF; 6]) {
        return TestResult::Fail("all-FF MAC reported valid");
    }
    if !mac_is_valid([0x00, 0xE0, 0x4C, 0x12, 0x34, 0x56]) {
        return TestResult::Fail("Realtek OUI MAC reported invalid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_mac_is_valid);

// ── 8. Name table round-trip ──────────────────────────────────────────────

fn smoke_rtlwifi_name_for_all_ids() -> TestResult {
    for &did in ALL_DEV_IDS {
        let n = name_for(did);
        if n == "rtlwifi" {
            return TestResult::Fail("name_for returned generic fallback for known ID");
        }
        if !n.starts_with("rtlwifi-") {
            return TestResult::Fail("name_for returned unexpected prefix");
        }
    }
    if name_for(0xDEAD) != "rtlwifi" {
        return TestResult::Fail("name_for unknown id should return 'rtlwifi'");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_name_for_all_ids);

// ── 9. CR register layout ─────────────────────────────────────────────────

fn smoke_rtlwifi_cr_open_bits() -> TestResult {
    let expected = CR_HCI_TXDMA_EN
        | CR_HCI_RXDMA_EN
        | CR_TXDMA_EN
        | CR_RXDMA_EN
        | CR_PROTOCOL_EN
        | CR_SCHEDULE_EN
        | CR_MAC_TX_EN
        | CR_MAC_RX_EN;
    if CR_OPEN != expected {
        return TestResult::Fail("CR_OPEN differs from OR of per-bit constants");
    }
    if CR_OPEN & 0xFF00 != 0 {
        return TestResult::Fail("CR_OPEN has bits set above bit 7");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_cr_open_bits);

// ── 10. Live-silicon probe skip ───────────────────────────────────────────

fn smoke_rtlwifi_probe_bound_or_skip() -> TestResult {
    if !super::pci::is_probed() {
        return TestResult::Skip("rtlwifi: no device bound (expected on QEMU)");
    }
    let mac = match super::pci::with_controller(|d| d.mac) {
        Some(m) => m,
        None => return TestResult::Skip("rtlwifi: probed but no controller"),
    };
    if !mac_is_valid(mac) {
        return TestResult::Fail("rtlwifi: bound device reports invalid EFUSE MAC");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_probe_bound_or_skip);
