//! rtlwifi smoke tests.
//!
//! All smokes are pure-data (no live MMIO): PCI-ID table coverage, EFUSE
//! descriptor layout, TX/RX descriptor field extraction, firmware blob-name
//! resolution, per-chip register-bank size table.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::btcoex::{
    encode_tdma, has_bt, pattern_for, BtState, TdmaPattern, WifiState, H2C_BT_TDMA,
};
use super::channel::{ch_to_freq_mhz, Bandwidth, ChannelError, DEFAULT_CHANNEL_24G};
use super::dma::{
    queue_register_table, ACTIVE_TX_QUEUES, REG_TXDMA_OFFSET_CHK, RX_RING_DEPTH, TXBD_SEG_NUM,
    TXDMA_BD_DESC_POLL, TX_RING_DEPTH_BE, TX_RING_DEPTH_DEFAULT,
};
use super::efuse::{mac_is_valid, EfuseError};
use super::fw::fw_name_for;
use super::h2c::{
    box_reg, H2cState, FWDL_CHKSUM_RPT, FW_PAGE_SIZE, FW_START_ADDRESS, MCUFWDL_RDY, REG_HMEBOX_0,
    REG_HMEBOX_3, REG_HMEBOX_EXT_0, REG_HMETFR, WINTINI_RDY,
};
use super::irq::{
    IsrStatus, HIMRE_DEFAULT, HIMR_DEFAULT, IMRE_RXFOVW, IMR_BEDOK, IMR_BKDOK, IMR_C2HCMD,
    IMR_HIGHDOK, IMR_MGNTDOK, IMR_PSTIMEOUT, IMR_RDU, IMR_ROK, IMR_VIDOK, IMR_VODOK,
};
use super::mac::{
    bd_num_reg_for_queue, desa_reg_for_queue, txpktbuf_bndy_for, RCR_DEFAULT, TCR_DEFAULT,
    TXPKTBUF_BNDY_8192EE,
};
use super::pci::{name_for, register_pci_driver};
use super::phy::{BB_BRINGUP_PREAMBLE, BB_RST_VALUE, RF_EN, RF_RSTB, RF_SDMRSTB};
use super::power::{
    power_on_table_for, WlanPwrCfg, PWR_BASEADDR_MAC, PWR_CMD_END, PWR_CMD_POLLING, PWR_CMD_WRITE,
    PWR_CUT_ALL_MSK, PWR_FAB_ALL_MSK, PWR_INTF_PCI_MSK, RTL8188EE_PWR_ON, RTL8192CE_PWR_ON,
    RTL8192EE_PWR_ON, RTL8723BE_PWR_ON, RTL8821AE_PWR_ON, RTL8822BE_PWR_ON,
};
use super::regs::*;
use super::rf::{lssi_pack, RfPath, RF_MASK_12};
use super::rtl8188ee::{RxDesc, TxDesc};
use super::vht::{has_vht, max_mcs_for, VhtMcs, VhtMode, REG_BWOPMODE};

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
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: REALTEK_VENDOR,
                    ..
                }
            )
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
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_pci_id_table_coverage
);

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
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_efuse_descriptor_layout
);

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
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_fw_blob_name_by_chip
);

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
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_per_chip_mmio_size_table
);

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
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_probe_bound_or_skip
);

// ── 11. Power-on table presence + terminator per chip ────────────────────

fn smoke_rtlwifi_power_on_tables_present() -> TestResult {
    let cases: &[(u16, &[WlanPwrCfg])] = &[
        (RTL_DEV_8188EE, RTL8188EE_PWR_ON),
        (RTL_DEV_8192CE, RTL8192CE_PWR_ON),
        (RTL_DEV_8192CE_ALT, RTL8192CE_PWR_ON),
        (RTL_DEV_8192DE, RTL8192CE_PWR_ON),
        (RTL_DEV_8192EE, RTL8192EE_PWR_ON),
        (RTL_DEV_8723AE, RTL8723BE_PWR_ON),
        (RTL_DEV_8723BE, RTL8723BE_PWR_ON),
        (RTL_DEV_8821AE, RTL8821AE_PWR_ON),
        (RTL_DEV_8822BE, RTL8822BE_PWR_ON),
    ];
    for &(did, expected) in cases {
        let got = match power_on_table_for(did) {
            Some(t) => t,
            None => return TestResult::Fail("rtlwifi: power_on_table_for None for known did"),
        };
        if got.as_ptr() != expected.as_ptr() {
            return TestResult::Fail("rtlwifi: power_on_table_for mapped wrong table");
        }
        let last = match got.last() {
            Some(r) => r,
            None => return TestResult::Fail("rtlwifi: empty power table"),
        };
        if last.cmd() != PWR_CMD_END {
            return TestResult::Fail("rtlwifi: power table not END-terminated");
        }
    }
    if power_on_table_for(0xFFFF).is_some() {
        return TestResult::Fail("rtlwifi: unknown DID got a table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_power_on_tables_present
);

// ── 12. Power-on row field packing ───────────────────────────────────────

fn smoke_rtlwifi_power_on_row_encoding() -> TestResult {
    let tables: &[&[WlanPwrCfg]] = &[
        RTL8188EE_PWR_ON,
        RTL8192CE_PWR_ON,
        RTL8192EE_PWR_ON,
        RTL8723BE_PWR_ON,
        RTL8821AE_PWR_ON,
        RTL8822BE_PWR_ON,
    ];
    for &t in tables {
        for row in t {
            if row.intf() & PWR_INTF_PCI_MSK == 0 {
                return TestResult::Fail("rtlwifi: power row missing PCI intf bit");
            }
            if row.cut_msk & PWR_CUT_ALL_MSK == 0 {
                return TestResult::Fail("rtlwifi: power row missing cut mask");
            }
            if row.fab() & PWR_FAB_ALL_MSK == 0 {
                return TestResult::Fail("rtlwifi: power row missing fab mask");
            }
            match row.cmd() {
                PWR_CMD_WRITE | PWR_CMD_POLLING | PWR_CMD_END => {}
                _ => {
                    if row.base() != PWR_BASEADDR_MAC {
                        return TestResult::Fail("rtlwifi: non-MAC base in PCIe table");
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_power_on_row_encoding
);

// ── 13. MAC TRX FIFO boundary per chip ───────────────────────────────────

fn smoke_rtlwifi_mac_trx_boundary_table() -> TestResult {
    // Every chip resolves to a non-zero page boundary value.
    for &did in ALL_DEV_IDS {
        let b = txpktbuf_bndy_for(did);
        if b == 0 {
            return TestResult::Fail("rtlwifi: zero TRX boundary for known DID");
        }
    }
    // Spot-check the 92EE canonical value.
    if txpktbuf_bndy_for(RTL_DEV_8192EE) != TXPKTBUF_BNDY_8192EE {
        return TestResult::Fail("rtlwifi: 8192EE boundary mismatch");
    }
    if txpktbuf_bndy_for(RTL_DEV_8192EE) != 0xF7 {
        return TestResult::Fail("rtlwifi: 8192EE boundary not 0xF7");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_mac_trx_boundary_table
);

// ── 14. MAC RCR + TCR defaults ───────────────────────────────────────────

fn smoke_rtlwifi_mac_rcr_tcr_defaults() -> TestResult {
    // RCR must accept APM + AM + AB + AMF + ACF (Linux 8192EE sw.c).
    let want = (1u32 << 1) | (1u32 << 2) | (1u32 << 3) | (1u32 << 7) | (1u32 << 6);
    if RCR_DEFAULT != want {
        return TestResult::Fail("RCR_DEFAULT does not match Linux 8192EE seed");
    }
    if TCR_DEFAULT != 0x0004_0404 {
        return TestResult::Fail("TCR_DEFAULT not 0x40404");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_mac_rcr_tcr_defaults
);

// ── 15. Per-queue DESA / TXBD_NUM register table ─────────────────────────

fn smoke_rtlwifi_per_queue_register_table() -> TestResult {
    // All 7 user-visible queues have both a DESA and TXBD_NUM register
    // mapped via the helpers in mac.rs.
    let queues = [
        BK_QUEUE,
        BE_QUEUE,
        VI_QUEUE,
        VO_QUEUE,
        BEACON_QUEUE,
        MGNT_QUEUE,
        HIGH_QUEUE,
    ];
    for q in queues {
        if desa_reg_for_queue(q).is_none() {
            return TestResult::Fail("desa_reg_for_queue returned None for known queue");
        }
        // Beacon doesn't have a TXBD_NUM in our table (chip-managed).
        if q != BEACON_QUEUE && bd_num_reg_for_queue(q).is_none() {
            return TestResult::Fail("bd_num_reg_for_queue returned None for known queue");
        }
    }
    // Unknown queue → None.
    if desa_reg_for_queue(99).is_some() {
        return TestResult::Fail("desa_reg_for_queue accepted invalid queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_per_queue_register_table
);

// ── 16. H2C mailbox bank selector + state advance ────────────────────────

fn smoke_rtlwifi_h2c_box_selector() -> TestResult {
    // box_reg(N) cycles HMEBOX_{0,1,2,3} and their EXT halves.
    if box_reg(0).0 != REG_HMEBOX_0 {
        return TestResult::Fail("box_reg(0) main not REG_HMEBOX_0");
    }
    if box_reg(0).1 != REG_HMEBOX_EXT_0 {
        return TestResult::Fail("box_reg(0) ext not REG_HMEBOX_EXT_0");
    }
    if box_reg(3).0 != REG_HMEBOX_3 {
        return TestResult::Fail("box_reg(3) main not REG_HMEBOX_3");
    }
    // box_reg wraps at 4.
    if box_reg(4).0 != REG_HMEBOX_0 {
        return TestResult::Fail("box_reg(4) didn't wrap");
    }
    // State advances 0→1→2→3→0.  Track by reading `next`.
    let mut s = H2cState::new();
    if s.next() != 0 {
        return TestResult::Fail("H2cState::new() next != 0");
    }
    // The full send-h2c can't run without MMIO; the state structure is
    // what we're verifying here.
    let _ = REG_HMETFR;
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_h2c_box_selector);

// ── 17. FW download constants ────────────────────────────────────────────

fn smoke_rtlwifi_fw_download_constants() -> TestResult {
    if FW_PAGE_SIZE != 4096 {
        return TestResult::Fail("FW_PAGE_SIZE not 4096");
    }
    if FW_START_ADDRESS != 0x1000 {
        return TestResult::Fail("FW_START_ADDRESS not 0x1000");
    }
    if MCUFWDL_RDY != 1 << 1 {
        return TestResult::Fail("MCUFWDL_RDY not BIT(1)");
    }
    if FWDL_CHKSUM_RPT != 1 << 2 {
        return TestResult::Fail("FWDL_CHKSUM_RPT not BIT(2)");
    }
    if WINTINI_RDY != 1 << 6 {
        return TestResult::Fail("WINTINI_RDY not BIT(6)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_fw_download_constants
);

// ── 18. PHY BB-bringup preamble + RF reset constants ─────────────────────

fn smoke_rtlwifi_phy_bringup_constants() -> TestResult {
    // BB bring-up preamble must have at least 3 rows.
    if BB_BRINGUP_PREAMBLE.len() < 3 {
        return TestResult::Fail("BB_BRINGUP_PREAMBLE too short");
    }
    // RF release-reset mask is RF_EN | RF_RSTB | RF_SDMRSTB.
    let want = RF_EN | RF_RSTB | RF_SDMRSTB;
    if want != 0x07 {
        return TestResult::Fail("RF release-reset mask not 0x07");
    }
    // BB_RST_VALUE includes both global + digital BB resets.
    if BB_RST_VALUE & (1 << 0) == 0 {
        return TestResult::Fail("BB_RST_VALUE missing BBRSTB");
    }
    if BB_RST_VALUE & (1 << 1) == 0 {
        return TestResult::Fail("BB_RST_VALUE missing PPLL / BB_GLB_RSTN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_phy_bringup_constants
);

// ── 19. RF LSSI packer ───────────────────────────────────────────────────

fn smoke_rtlwifi_rf_lssi_pack() -> TestResult {
    // Packing the RF[0x18] write of 0x8000 (LC trim trigger) must place
    // the address at bits[19:16] and the data at bits[11:0].
    let pkt = lssi_pack(0x18, 0x0800);
    if (pkt >> 16) & 0x0F != 0x08 {
        return TestResult::Fail("lssi_pack: address not in bits[19:16]");
    }
    if pkt & RF_MASK_12 != 0x0800 {
        return TestResult::Fail("lssi_pack: data not in low 12 bits");
    }
    // Make sure RfPath maps to distinct LSSI write registers.
    let a = RfPath::A;
    let b = RfPath::B;
    if (a as u8) == (b as u8) {
        return TestResult::Fail("RfPath enum collapsed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_rf_lssi_pack);

// ── 20. DMA ring depths + segment count ──────────────────────────────────

fn smoke_rtlwifi_dma_ring_depths() -> TestResult {
    if TX_RING_DEPTH_BE != 256 {
        return TestResult::Fail("BE TX ring depth not 256");
    }
    if TX_RING_DEPTH_DEFAULT != 128 {
        return TestResult::Fail("default TX ring depth not 128");
    }
    if RX_RING_DEPTH != 512 {
        return TestResult::Fail("RX ring depth not 512");
    }
    if TXBD_SEG_NUM != 8 {
        return TestResult::Fail("TXBD seg-num not 8");
    }
    if TXDMA_BD_DESC_POLL != 1u32 << 30 {
        return TestResult::Fail("TXDMA doorbell bit not BIT(30)");
    }
    let _ = REG_TXDMA_OFFSET_CHK;
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_dma_ring_depths);

// ── 21. DMA per-queue programming table ──────────────────────────────────

fn smoke_rtlwifi_dma_queue_register_table() -> TestResult {
    let table = queue_register_table();
    // Three TX queues = BE + MGT + HI.
    if table.len() != ACTIVE_TX_QUEUES.len() {
        return TestResult::Fail("queue_register_table length mismatch");
    }
    for &(q, desa, bdnum) in &table {
        if !ACTIVE_TX_QUEUES.contains(&q) {
            return TestResult::Fail("queue_register_table returned non-active queue");
        }
        if desa == 0 || bdnum == 0 {
            return TestResult::Fail("queue_register_table returned zero register");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_dma_queue_register_table
);

// ── 22. IRQ HIMR default mask carries every TX queue completion ──────────

fn smoke_rtlwifi_irq_himr_default() -> TestResult {
    // Every TX completion bit must be set.
    let want = IMR_PSTIMEOUT
        | IMR_C2HCMD
        | IMR_HIGHDOK
        | IMR_MGNTDOK
        | IMR_BKDOK
        | IMR_BEDOK
        | IMR_VIDOK
        | IMR_VODOK
        | IMR_RDU
        | IMR_ROK;
    if HIMR_DEFAULT != want {
        return TestResult::Fail("HIMR_DEFAULT mismatch with Linux 8192EE seed");
    }
    if HIMRE_DEFAULT != IMRE_RXFOVW {
        return TestResult::Fail("HIMRE_DEFAULT not RXFOVW");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_irq_himr_default);

// ── 23. IRQ ISR status accessors ─────────────────────────────────────────

fn smoke_rtlwifi_irq_isr_accessors() -> TestResult {
    let mut st = IsrStatus {
        hisr: IMR_BEDOK | IMR_ROK,
        hisre: 0,
    };
    if !st.rx_ready() {
        return TestResult::Fail("rx_ready missed IMR_ROK");
    }
    if !st.tx_be_done() {
        return TestResult::Fail("tx_be_done missed IMR_BEDOK");
    }
    if !st.tx_any_done() {
        return TestResult::Fail("tx_any_done missed any TX done bit");
    }
    if st.rx_overflow() {
        return TestResult::Fail("rx_overflow false-positive");
    }
    st.hisre = IMRE_RXFOVW;
    if !st.rx_overflow() {
        return TestResult::Fail("rx_overflow missed RXFOVW");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_irq_isr_accessors);

// ── 24. Channel 1 freq + bandwidth modes ─────────────────────────────────

fn smoke_rtlwifi_channel_freq_table() -> TestResult {
    if DEFAULT_CHANNEL_24G != 1 {
        return TestResult::Fail("default 2.4 GHz channel not 1");
    }
    if ch_to_freq_mhz(1) != 2412 {
        return TestResult::Fail("ch 1 freq not 2412 MHz");
    }
    if ch_to_freq_mhz(6) != 2437 {
        return TestResult::Fail("ch 6 freq not 2437 MHz");
    }
    if ch_to_freq_mhz(11) != 2462 {
        return TestResult::Fail("ch 11 freq not 2462 MHz");
    }
    if ch_to_freq_mhz(14) != 2484 {
        return TestResult::Fail("ch 14 freq not 2484 MHz");
    }
    if ch_to_freq_mhz(36) != 5180 {
        return TestResult::Fail("ch 36 freq not 5180 MHz");
    }
    if ch_to_freq_mhz(0) != 0 {
        return TestResult::Fail("ch 0 not rejected");
    }
    if ch_to_freq_mhz(200) != 0 {
        return TestResult::Fail("ch 200 not rejected");
    }
    // Bandwidth enum encoding distinct.
    if Bandwidth::Ht20 as u8 == Bandwidth::Ht40 as u8 {
        return TestResult::Fail("Bandwidth enum collapsed");
    }
    let _ = ChannelError::OutOfRange;
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_channel_freq_table);

// ── 25. BT-coex classifier + TDMA encoding ───────────────────────────────

fn smoke_rtlwifi_btcoex_matrix() -> TestResult {
    // Combo silicon has BT; pure Wi-Fi chips do not.
    let combo = [RTL_DEV_8723AE, RTL_DEV_8723BE, RTL_DEV_8821AE];
    for did in combo {
        if !has_bt(did) {
            return TestResult::Fail("combo chip not classified as BT-capable");
        }
    }
    let pure_wifi = [RTL_DEV_8188EE, RTL_DEV_8192EE, RTL_DEV_8822BE];
    for did in pure_wifi {
        if has_bt(did) {
            return TestResult::Fail("non-combo chip mis-classified as BT-capable");
        }
    }
    // Idle/idle → WifiOnly.
    if pattern_for(WifiState::Idle, BtState::Idle) != TdmaPattern::WifiOnly {
        return TestResult::Fail("matrix: idle/idle != WifiOnly");
    }
    // Connected/Streaming → Shared.
    if pattern_for(WifiState::Connected, BtState::Streaming) != TdmaPattern::Shared {
        return TestResult::Fail("matrix: connected/streaming != Shared");
    }
    // Encoding non-empty.
    if encode_tdma(TdmaPattern::Shared) == [0; 5] {
        return TestResult::Fail("encode_tdma(Shared) returned all-zero pattern");
    }
    if H2C_BT_TDMA != 0x66 {
        return TestResult::Fail("H2C_BT_TDMA not 0x66");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_btcoex_matrix);

// ── 26. VHT-capability classifier + MCS picker ───────────────────────────

fn smoke_rtlwifi_vht_capability() -> TestResult {
    if !has_vht(RTL_DEV_8821AE) {
        return TestResult::Fail("8821AE should be VHT-capable");
    }
    if !has_vht(RTL_DEV_8822BE) {
        return TestResult::Fail("8822BE should be VHT-capable");
    }
    for did in [RTL_DEV_8188EE, RTL_DEV_8192EE, RTL_DEV_8723BE] {
        if has_vht(did) {
            return TestResult::Fail("HT-only chip mis-classified as VHT");
        }
    }
    // 8821AE is 1T1R → MCS9 only.
    if max_mcs_for(RTL_DEV_8821AE) != Some(VhtMcs::Vht1ssMcs9) {
        return TestResult::Fail("8821AE max MCS not 1ssMCS9");
    }
    // 8822BE is 2T2R → 2ss MCS9.
    if max_mcs_for(RTL_DEV_8822BE) != Some(VhtMcs::Vht2ssMcs9) {
        return TestResult::Fail("8822BE max MCS not 2ssMCS9");
    }
    if VhtMode::Bw20 as u8 == VhtMode::Bw80 as u8 {
        return TestResult::Fail("VhtMode enum collapsed");
    }
    if REG_BWOPMODE != 0x0603 {
        return TestResult::Fail("REG_BWOPMODE not 0x0603");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi", smoke_rtlwifi_vht_capability);

// ── 27. Per-chip name + power-on + fw resolution coverage ────────────────

fn smoke_rtlwifi_per_chip_coverage_matrix() -> TestResult {
    // For every chip in the family, every per-chip lookup must succeed.
    // Encodes the per-chip "complete" matrix from the brief.
    for &did in ALL_DEV_IDS {
        // 1) Name resolves.
        if name_for(did) == "rtlwifi" {
            return TestResult::Fail("name_for: generic fallback for known chip");
        }
        // 2) Power-on table resolves.
        if power_on_table_for(did).is_none() {
            return TestResult::Fail("power_on_table_for: missing entry");
        }
        // 3) FW blob name resolves.
        if fw_name_for(did).is_none() {
            return TestResult::Fail("fw_name_for: missing entry");
        }
        // 4) TRX FIFO boundary is set.
        if txpktbuf_bndy_for(did) == 0 {
            return TestResult::Fail("txpktbuf_bndy_for: zero");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_per_chip_coverage_matrix
);

// ── 28. Per-chip BT-coex + VHT feature flag matrix ───────────────────────

fn smoke_rtlwifi_per_chip_feature_flags() -> TestResult {
    let cases: &[(u16, bool, bool)] = &[
        // (did, has_bt, has_vht)
        (RTL_DEV_8188EE, false, false),
        (RTL_DEV_8192CE, false, false),
        (RTL_DEV_8192CE_ALT, false, false),
        (RTL_DEV_8192DE, false, false),
        (RTL_DEV_8192EE, false, false),
        (RTL_DEV_8723AE, true, false),
        (RTL_DEV_8723BE, true, false),
        (RTL_DEV_8821AE, true, true),
        (RTL_DEV_8822BE, false, true),
    ];
    for &(did, want_bt, want_vht) in cases {
        if has_bt(did) != want_bt {
            return TestResult::Fail("has_bt classification mismatch for chip");
        }
        if has_vht(did) != want_vht {
            return TestResult::Fail("has_vht classification mismatch for chip");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_per_chip_feature_flags
);
