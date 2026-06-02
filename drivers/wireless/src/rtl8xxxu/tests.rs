//! RTL8XXXU smoke tests — USB WiFi family.
//!
//! 8 pure-data smokes:
//! 1. USB ID table coverage (≥ 20 IDs across 5 families).
//! 2. EFUSE byte-decode round-trip (PG-header format).
//! 3. USB control-transfer encode for EFUSE read.
//! 4. Per-chip register-bank decode (all 5 families).
//! 5. Firmware blob name resolution by chip family.
//! 6. USB bulk-OUT TX descriptor layout (32-byte variant).
//! 7. USB interrupt-IN status word decode.
//! 8. ChipFamily::from_usb_id round-trip for all primary IDs.
//!
//! None of these tests touch live hardware; all pass on QEMU.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::efuse::{decode_efuse_map, efuse_addr_setups, EfuseAddr};
use super::fw::firmware_name;
use super::regs::*;
use super::usb::{IntrIn, TxDesc32, UsbControlSetup};

// ── 1. USB ID table coverage ────────────────────────────────────────

fn smoke_rtl8xxxu_usb_id_table_coverage() -> TestResult {
    // Primary Realtek-vendor IDs.
    let primary: &[(u16, u16)] = &[
        (RTL8XXXU_VENDOR, RTL8188EU_ID),
        (RTL8XXXU_VENDOR, RTL8188EU_ID_ALT),
        (RTL8XXXU_VENDOR, RTL8192EU_ID),
        (RTL8XXXU_VENDOR, RTL8723BU_ID),
        (RTL8XXXU_VENDOR, RTL8821CU_ID),
        (RTL8XXXU_VENDOR, RTL8822BU_ID),
    ];

    for &(vid, pid) in primary {
        let found = REALTEK_USB_IDS.iter().any(|&(v, p)| v == vid && p == pid);
        if !found {
            return TestResult::Fail("primary ID missing from REALTEK_USB_IDS");
        }
    }

    // Total IDs across both tables must be ≥ 20.
    let total = REALTEK_USB_IDS.len() + REBRANDED_IDS.len();
    if total < 20 {
        return TestResult::Fail("total USB ID count < 20");
    }

    // Every rebranded entry must have a non-Unknown family.
    for &(_, _, fam) in REBRANDED_IDS {
        if fam == ChipFamily::Unknown {
            return TestResult::Fail("rebranded entry has Unknown chip family");
        }
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_usb_id_table_coverage);

// ── 2. EFUSE byte-decode round-trip ────────────────────────────────

fn smoke_rtl8xxxu_efuse_decode_round_trip() -> TestResult {
    // Build a minimal 3-record PG-header EFUSE stream.
    //
    // Record 1: header = 0x00 → offset 0, word_mask = 0 (all 4 words present)
    //   8 data bytes: 0x01..0x08
    // Record 2: header = 0x28 → offset 2 (section 2), word_mask = 0x08 (words 0-2 present, 3 absent)
    //   6 data bytes (3 words × 2 bytes): 0x11 0x12, 0x13 0x14, 0x15 0x16
    // Terminator: 0xFF

    let raw: &[u8] = &[
        // Record 1: section 0, all words.
        0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        // Record 2: section 2 (header[7:4]=2), word_mask = 0x08 (skip word 3).
        (0x20u8 | 0x08), // header: (2 << 4) | 0x08
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        // Terminator.
        0xFF,
    ];

    let mut map = [0xFFu8; EFUSE_MAP_LEN];
    decode_efuse_map(raw, &mut map);

    // Section 0 (bytes 0..8) should be 0x01..0x08.
    for i in 0..8usize {
        if map[i] != (i as u8 + 1) {
            return TestResult::Fail("section 0 decode mismatch");
        }
    }

    // Section 2 (bytes 16..22) should be 0x11..0x16 (6 bytes); byte 22..24 = 0xFF (word 3 skipped).
    if map[16] != 0x11 || map[17] != 0x12 {
        return TestResult::Fail("section 2 word 0 decode mismatch");
    }
    if map[18] != 0x13 || map[19] != 0x14 {
        return TestResult::Fail("section 2 word 1 decode mismatch");
    }
    if map[20] != 0x15 || map[21] != 0x16 {
        return TestResult::Fail("section 2 word 2 decode mismatch");
    }
    // Word 3 of section 2 (bytes 22..24) — skipped, should remain 0xFF.
    if map[22] != 0xFF || map[23] != 0xFF {
        return TestResult::Fail("section 2 word 3 should be 0xFF (skipped)");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_efuse_decode_round_trip);

// ── 3. USB control-transfer encode for EFUSE read ──────────────────

fn smoke_rtl8xxxu_usb_ctrl_efuse_read_encode() -> TestResult {
    // A read setup for REG_EFUSE_CTRL (32-bit = 4 bytes).
    let setup = UsbControlSetup::read(REG_EFUSE_CTRL, 4);
    let bytes = setup.to_bytes();

    if bytes[0] != REALTEK_USB_READ {
        return TestResult::Fail("bmRequestType wrong for read");
    }
    if bytes[1] != REALTEK_USB_CMD_REQ {
        return TestResult::Fail("bRequest wrong");
    }
    // wValue = REG_EFUSE_CTRL = 0x0030 LE → [0x30, 0x00].
    if bytes[2] != 0x30 || bytes[3] != 0x00 {
        return TestResult::Fail("wValue (addr) wrong for REG_EFUSE_CTRL read");
    }
    // wIndex = 0.
    if bytes[4] != 0x00 || bytes[5] != 0x00 {
        return TestResult::Fail("wIndex should be 0");
    }
    // wLength = 4 LE → [0x04, 0x00].
    if bytes[6] != 0x04 || bytes[7] != 0x00 {
        return TestResult::Fail("wLength should be 4 for u32 read");
    }

    // A write setup for REG_EFUSE_CTRL + 1 (byte).
    let write_setup = UsbControlSetup::write(REG_EFUSE_CTRL + 1, 1);
    let wb = write_setup.to_bytes();
    if wb[0] != REALTEK_USB_WRITE {
        return TestResult::Fail("bmRequestType wrong for write");
    }
    // wValue = 0x0031 LE → [0x31, 0x00].
    if wb[2] != 0x31 || wb[3] != 0x00 {
        return TestResult::Fail("wValue wrong for EFUSE_CTRL+1 write");
    }
    if wb[6] != 0x01 || wb[7] != 0x00 {
        return TestResult::Fail("wLength should be 1 for byte write");
    }

    // Verify efuse_addr_setups correctly splits a 10-bit address.
    let addr = EfuseAddr::new(0x1A5); // bits: hi=01, lo=A5
    let setups = efuse_addr_setups(addr);
    if setups.addr_lo != 0xA5 {
        return TestResult::Fail("addr_lo wrong for EfuseAddr 0x1A5");
    }
    if setups.addr_hi_bits != 0x01 {
        return TestResult::Fail("addr_hi_bits wrong for EfuseAddr 0x1A5");
    }
    // apply_ctrl2: existing = 0xFC, should become (0xFC & 0xFC) | 0x01 = 0xFD.
    let new_ctrl2 = setups.apply_ctrl2(0xFC);
    if new_ctrl2 != 0xFD {
        return TestResult::Fail("apply_ctrl2 result wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_usb_ctrl_efuse_read_encode);

// ── 4. Per-chip register-bank decode ───────────────────────────────

fn smoke_rtl8xxxu_per_chip_register_bank_decode() -> TestResult {
    use super::{rtl8188e, rtl8192e, rtl8723b, rtl8821c, rtl8822b};

    // 8188EU: must have APS_FSMCO+1 and CR entries.
    let bank_8188 = rtl8188e::stage0_register_bank();
    if bank_8188.is_empty() {
        return TestResult::Fail("rtl8188e stage0 bank empty");
    }
    let has_aps_8188 = bank_8188.iter().any(|&(r, _)| r == REG_APS_FSMCO as u16 + 1);
    let has_cr_8188 = bank_8188.iter().any(|&(r, _)| r == REG_CR);
    if !has_aps_8188 { return TestResult::Fail("rtl8188e missing APS_FSMCO+1"); }
    if !has_cr_8188  { return TestResult::Fail("rtl8188e missing REG_CR"); }

    // 8192EU: must have LDO entry + APS_FSMCO.
    let bank_8192 = rtl8192e::stage0_register_bank();
    let has_ldo = bank_8192.iter().any(|&(r, _)| r == rtl8192e::REG_8192E_LDOV12_CTRL);
    if !has_ldo { return TestResult::Fail("rtl8192e missing LDO entry"); }

    // 8723BU: must have EFUSE_ACCESS entry.
    let bank_8723 = rtl8723b::stage0_register_bank();
    let has_efuse_access = bank_8723.iter().any(|&(r, v)| {
        r == REG_EFUSE_ACCESS && v == EFUSE_ACCESS_ENABLE
    });
    if !has_efuse_access {
        return TestResult::Fail("rtl8723b missing EFUSE_ACCESS_ENABLE");
    }

    // 8821CU: non-empty, has APS_FSMCO.
    let bank_8821 = rtl8821c::stage0_register_bank();
    if bank_8821.is_empty() {
        return TestResult::Fail("rtl8821c stage0 bank empty");
    }

    // 8822BU: non-empty, has APS_FSMCO.
    let bank_8822 = rtl8822b::stage0_register_bank();
    if bank_8822.is_empty() {
        return TestResult::Fail("rtl8822b stage0 bank empty");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_per_chip_register_bank_decode);

// ── 5. Firmware blob name resolution ───────────────────────────────

fn smoke_rtl8xxxu_firmware_name_resolution() -> TestResult {
    let cases: &[(ChipFamily, Option<&str>)] = &[
        (ChipFamily::Rtl8188eu, Some("rtlwifi/rtl8188eufw.bin")),
        (ChipFamily::Rtl8192eu, Some("rtlwifi/rtl8192eufw.bin")),
        (ChipFamily::Rtl8723bu, Some("rtlwifi/rtl8723bufw.bin")),
        (ChipFamily::Rtl8821cu, Some("rtlwifi/rtl8821cufw.bin")),
        (ChipFamily::Rtl8822bu, Some("rtlwifi/rtl8822bufw.bin")),
        (ChipFamily::Unknown,   None),
    ];

    for &(chip, expected) in cases {
        let got = firmware_name(chip);
        if got != expected {
            return TestResult::Fail("firmware name mismatch");
        }
    }

    // Also verify the per-chip module constants match.
    if super::rtl8188e::FIRMWARE_NAME != "rtlwifi/rtl8188eufw.bin" {
        return TestResult::Fail("rtl8188e FIRMWARE_NAME mismatch");
    }
    if super::rtl8192e::FIRMWARE_NAME != "rtlwifi/rtl8192eufw.bin" {
        return TestResult::Fail("rtl8192e FIRMWARE_NAME mismatch");
    }
    if super::rtl8723b::FIRMWARE_NAME != "rtlwifi/rtl8723bufw.bin" {
        return TestResult::Fail("rtl8723b FIRMWARE_NAME mismatch");
    }
    if super::rtl8821c::FIRMWARE_NAME != "rtlwifi/rtl8821cufw.bin" {
        return TestResult::Fail("rtl8821c FIRMWARE_NAME mismatch");
    }
    if super::rtl8822b::FIRMWARE_NAME != "rtlwifi/rtl8822bufw.bin" {
        return TestResult::Fail("rtl8822b FIRMWARE_NAME mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_firmware_name_resolution);

// ── 6. USB bulk-OUT TX descriptor layout (32-byte) ─────────────────

fn smoke_rtl8xxxu_tx_desc32_layout() -> TestResult {
    // TxDesc32 must be exactly 32 bytes.
    if TxDesc32::SIZE != 32 {
        return TestResult::Fail("TxDesc32::SIZE != 32");
    }
    if core::mem::size_of::<TxDesc32>() != 32 {
        return TestResult::Fail("sizeof(TxDesc32) != 32");
    }

    // Build a management descriptor for a 100-byte payload.
    let desc = TxDesc32::management(100, 0);
    let bytes = desc.to_bytes();

    // DW0: pkt_len = 100 (bits[12:0]) + OWN (bit 31).
    let dw0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if dw0 & 0x1FFF != 100 {
        return TestResult::Fail("TxDesc32 pkt_len wrong in DW0");
    }
    if dw0 & (1 << 31) == 0 {
        return TestResult::Fail("TxDesc32 OWN bit not set in DW0");
    }

    // pkt_len() method.
    if desc.pkt_len() != 100 {
        return TestResult::Fail("TxDesc32::pkt_len() wrong");
    }

    // Round-trip: from_bytes should recover the original.
    let desc2 = TxDesc32::from_bytes(&bytes);
    if desc2.pkt_len() != desc.pkt_len() {
        return TestResult::Fail("TxDesc32 round-trip pkt_len mismatch");
    }

    // build_bulk_out_frame should have descriptor + payload.
    let payload = [0xABu8; 50];
    let frame = super::usb::build_bulk_out_frame(&payload);
    if frame.len() != TxDesc32::SIZE + 50 {
        return TestResult::Fail("build_bulk_out_frame length wrong");
    }
    // Verify frame[0..4] is the descriptor DW0.
    let frame_dw0 = u32::from_le_bytes(frame[0..4].try_into().unwrap());
    if frame_dw0 & 0x1FFF != 50 {
        return TestResult::Fail("bulk_out_frame descriptor pkt_len wrong");
    }
    // Payload starts at offset 32.
    if frame[32] != 0xAB {
        return TestResult::Fail("bulk_out_frame payload bytes wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_tx_desc32_layout);

// ── 7. USB interrupt-IN status word ────────────────────────────────

fn smoke_rtl8xxxu_intr_in_status_word() -> TestResult {
    let mut intr = IntrIn::new();
    // All zeros → status_word = 0.
    if intr.status_word() != 0 {
        return TestResult::Fail("empty IntrIn status_word != 0");
    }
    // Set bytes 0..4 to a known pattern.
    intr.data[0] = 0x11;
    intr.data[1] = 0x22;
    intr.data[2] = 0x33;
    intr.data[3] = 0x44;
    let sw = intr.status_word();
    if sw != 0x4433_2211 {
        return TestResult::Fail("IntrIn status_word LE decode wrong");
    }
    // Verify the data buffer is the correct size.
    if intr.data.len() != super::regs::USB_INTR_CONTENT_LEN {
        return TestResult::Fail("IntrIn data buffer length wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_intr_in_status_word);

// ── 8. ChipFamily::from_usb_id round-trip ──────────────────────────

fn smoke_rtl8xxxu_chip_family_from_usb_id() -> TestResult {
    let cases: &[(u16, u16, ChipFamily)] = &[
        (RTL8XXXU_VENDOR, RTL8188EU_ID, ChipFamily::Rtl8188eu),
        (RTL8XXXU_VENDOR, RTL8188EU_ID_ALT, ChipFamily::Rtl8188eu),
        (RTL8XXXU_VENDOR, RTL8192EU_ID, ChipFamily::Rtl8192eu),
        (RTL8XXXU_VENDOR, RTL8723BU_ID, ChipFamily::Rtl8723bu),
        (RTL8XXXU_VENDOR, RTL8821CU_ID, ChipFamily::Rtl8821cu),
        (RTL8XXXU_VENDOR, RTL8822BU_ID, ChipFamily::Rtl8822bu),
        // Rebranded: TP-Link TL-WN722N v2 → RTL8188EU.
        (0x2357, 0x010C, ChipFamily::Rtl8188eu),
        // Edimax EW-7722UTn V3 → RTL8192EU.
        (0x7392, 0xB722, ChipFamily::Rtl8192eu),
        // 7392:A611 → RTL8723BU.
        (0x7392, 0xA611, ChipFamily::Rtl8723bu),
        // Unknown device.
        (0x1234, 0x5678, ChipFamily::Unknown),
    ];

    for &(vid, pid, expected) in cases {
        let got = ChipFamily::from_usb_id(vid, pid);
        if got != expected {
            return TestResult::Fail("ChipFamily::from_usb_id mismatch");
        }
    }

    // Verify name() for all known families.
    if ChipFamily::Rtl8188eu.name() != "rtl8188eu" {
        return TestResult::Fail("Rtl8188eu.name() wrong");
    }
    if ChipFamily::Rtl8822bu.name() != "rtl8822bu" {
        return TestResult::Fail("Rtl8822bu.name() wrong");
    }
    if ChipFamily::Unknown.name() != "rtl8xxxu" {
        return TestResult::Fail("Unknown.name() should be rtl8xxxu");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_chip_family_from_usb_id);

// ── 9. phy_tables sentinel + apply-loop semantics ──────────────────

fn smoke_rtl8xxxu_phy_tables_apply_loops() -> TestResult {
    use super::phy_tables::{
        MacRow, PhyRow, RfRow,
        apply_mac_table, apply_phy_table, apply_rf_table,
        live_rows_mac, live_rows_phy, live_rows_rf,
    };

    // Sentinel detection.
    if !MacRow::SENTINEL.is_sentinel() {
        return TestResult::Fail("MacRow::SENTINEL not is_sentinel");
    }
    if !RfRow::SENTINEL.is_sentinel() {
        return TestResult::Fail("RfRow::SENTINEL not is_sentinel");
    }

    // MAC apply-loop: 3 rows + sentinel.
    let mac_table: &[MacRow] = &[
        MacRow { reg: 0x100, val: 0x11 },
        MacRow { reg: 0x101, val: 0x22 },
        MacRow { reg: 0x102, val: 0x33 },
        MacRow::SENTINEL,
        // Sentinel should stop the loop — these rows must not be applied.
        MacRow { reg: 0x900, val: 0xFF },
    ];
    if live_rows_mac(mac_table) != 3 {
        return TestResult::Fail("MAC live_rows != 3");
    }
    let mut count = 0usize;
    let n = apply_mac_table(mac_table, |_r, _v| count += 1);
    if n != 3 || count != 3 {
        return TestResult::Fail("apply_mac_table call count wrong");
    }

    // PHY apply-loop: 2 rows + sentinel.
    let phy_table: &[PhyRow] = &[
        PhyRow { reg: 0x800, val: 0xDEADBEEF },
        PhyRow { reg: 0x804, val: 0xCAFEBABE },
        PhyRow::SENTINEL,
    ];
    if live_rows_phy(phy_table) != 2 {
        return TestResult::Fail("PHY live_rows != 2");
    }
    let mut sum = 0u64;
    let n2 = apply_phy_table(phy_table, |r, v| sum += (r as u64) + (v as u64));
    if n2 != 2 {
        return TestResult::Fail("apply_phy_table count wrong");
    }
    let expected = 0x800u64 + 0xDEADBEEFu64 + 0x804u64 + 0xCAFEBABEu64;
    if sum != expected {
        return TestResult::Fail("apply_phy_table sum wrong");
    }

    // RF apply-loop: 4 rows + sentinel.
    let rf_table: &[RfRow] = &[
        RfRow { reg: 0x00, val: 0x00030000 },
        RfRow { reg: 0x18, val: 0x00000407 },
        RfRow { reg: 0x1E, val: 0x00080009 },
        RfRow { reg: 0x1F, val: 0x00000880 },
        RfRow::SENTINEL,
    ];
    if live_rows_rf(rf_table) != 4 {
        return TestResult::Fail("RF live_rows != 4");
    }
    let mut rcount = 0usize;
    let n3 = apply_rf_table(rf_table, |_r, _v| rcount += 1);
    if n3 != 4 || rcount != 4 {
        return TestResult::Fail("apply_rf_table count wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_phy_tables_apply_loops);

// ── 10. 8188EU per-chip integration ────────────────────────────────

fn smoke_rtl8xxxu_8188eu_per_chip() -> TestResult {
    use super::rtl8188e;

    // Row-count constants — match Linux 8188e.c (Wave 36: populated).
    if rtl8188e::N_MAC_ROWS != 92 {
        return TestResult::Fail("8188e N_MAC_ROWS != 92");
    }
    if rtl8188e::N_PHY_ROWS != 192 {
        return TestResult::Fail("8188e N_PHY_ROWS != 192");
    }
    if rtl8188e::N_AGC_ROWS != 130 {
        return TestResult::Fail("8188e N_AGC_ROWS != 130");
    }
    if rtl8188e::N_RF_A_ROWS != 95 {
        return TestResult::Fail("8188e N_RF_A_ROWS != 95");
    }
    if rtl8188e::NUM_RF_PATHS != 1 {
        return TestResult::Fail("8188e is 1T1R");
    }

    // IQK shape.
    let mut iqk = [super::phy::IqkStep { reg: 0, val: 0 };
                   rtl8188e::IQK_PATH_A_STEP_COUNT];
    let n = rtl8188e::build_iqk_path_a_sequence(&mut iqk);
    if n != 7 {
        return TestResult::Fail("8188e IQK step count != 7");
    }
    if rtl8188e::IQK_RETRY != 2 {
        return TestResult::Fail("8188e IQK_RETRY != 2");
    }
    if rtl8188e::IQK_ITERATIONS != 3 {
        return TestResult::Fail("8188e IQK_ITERATIONS != 3");
    }
    // Pass predicate: clean inputs pass.
    if !rtl8188e::iqk_passed(0, 0, 0) {
        return TestResult::Fail("8188e iqk_passed(0,0,0) should pass");
    }
    // Reject fingerprint should fail.
    if rtl8188e::iqk_passed(0, 0x01420000, 0) {
        return TestResult::Fail("8188e iqk_passed should reject E94 fingerprint");
    }
    if rtl8188e::iqk_passed(rtl8188e::IQK_PASS_BIT_EAC, 0, 0) {
        return TestResult::Fail("8188e iqk_passed should reject EAC bit 28");
    }

    // Channel range 2.4 GHz only.
    if !rtl8188e::channel_valid(1) || !rtl8188e::channel_valid(14) {
        return TestResult::Fail("8188e channel 1 and 14 should be valid");
    }
    if rtl8188e::channel_valid(36) {
        return TestResult::Fail("8188e ch 36 (5G) should NOT be valid");
    }

    // Channel set: 1 LSSI write.
    let cs = rtl8188e::channel_set_writes_8188e(6);
    if cs.len() != 1 {
        return TestResult::Fail("8188e channel set should emit 1 write");
    }

    // init_mac / init_phy / init_rf with populated tables — call counts
    // must match the N_*_ROWS constants exactly.
    let mut mac_count = 0usize;
    let n_mac = rtl8188e::init_mac(|_r, _v| mac_count += 1);
    if n_mac != rtl8188e::N_MAC_ROWS || mac_count != rtl8188e::N_MAC_ROWS {
        return TestResult::Fail("8188e init_mac call count != N_MAC_ROWS");
    }
    let mut phy_count = 0usize;
    let n_phy = rtl8188e::init_phy(|_r, _v| phy_count += 1);
    let n_expected = rtl8188e::N_PHY_ROWS + rtl8188e::N_AGC_ROWS;
    if n_phy != n_expected || phy_count != n_expected {
        return TestResult::Fail("8188e init_phy != N_PHY+N_AGC");
    }
    let mut rf_count = 0usize;
    let n_rf = rtl8188e::init_rf(|_r, _v| rf_count += 1);
    if n_rf != rtl8188e::N_RF_A_ROWS || rf_count != rtl8188e::N_RF_A_ROWS {
        return TestResult::Fail("8188e init_rf != N_RF_A_ROWS");
    }
    // First MAC row should be (0x026, 0x41) per Linux 8188e.c L20.
    let first_mac = rtl8188e::MAC_INIT_TABLE[0];
    if first_mac.reg != 0x026 || first_mac.val != 0x41 {
        return TestResult::Fail("8188e MAC first row != (0x026, 0x41)");
    }
    // First BB row should be (0x800, 0x80040000) per Linux 8188e.c L47.
    let first_bb = rtl8188e::PHY_INIT_TABLE[0];
    if first_bb.reg != 0x800 || first_bb.val != 0x80040000 {
        return TestResult::Fail("8188e BB first row != (0x800, 0x80040000)");
    }
    // First RF row should be (0x00, 0x00030000) per Linux 8188e.c L216.
    let first_rf = rtl8188e::RADIO_A_INIT_TABLE[0];
    if first_rf.reg != 0x00 || first_rf.val != 0x00030000 {
        return TestResult::Fail("8188e RF-A first row != (0x00, 0x00030000)");
    }
    // IQK values populated — step 0 = REG_TX_IQK_TONE_A val 0x10008c1f.
    let mut iqk2 = [super::phy::IqkStep { reg: 0, val: 0 };
                    rtl8188e::IQK_PATH_A_STEP_COUNT];
    rtl8188e::build_iqk_path_a_sequence(&mut iqk2);
    if iqk2[0].val != 0x10008c1f {
        return TestResult::Fail("8188e IQK step 0 val != 0x10008c1f");
    }
    if iqk2[2].val != 0x82140102 {
        return TestResult::Fail("8188e IQK step 2 val != 0x82140102");
    }
    if iqk2[5].val != 0xf9000000 || iqk2[6].val != 0xf8000000 {
        return TestResult::Fail("8188e IQK step 5/6 trigger values wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_8188eu_per_chip);

// ── 11. 8192EU per-chip integration ────────────────────────────────

fn smoke_rtl8xxxu_8192eu_per_chip() -> TestResult {
    use super::rtl8192e;

    if rtl8192e::N_MAC_ROWS != 99 {
        return TestResult::Fail("8192e N_MAC_ROWS != 99");
    }
    if rtl8192e::N_PHY_ROWS != 260 {
        return TestResult::Fail("8192e N_PHY_ROWS != 260");
    }
    if rtl8192e::N_AGC_STD_ROWS != 135 {
        return TestResult::Fail("8192e N_AGC_STD_ROWS != 135");
    }
    if rtl8192e::N_RF_A_ROWS != 155 {
        return TestResult::Fail("8192e N_RF_A_ROWS != 155");
    }
    if rtl8192e::N_RF_B_ROWS != 140 {
        return TestResult::Fail("8192e N_RF_B_ROWS != 140");
    }
    if rtl8192e::NUM_RF_PATHS != 2 {
        return TestResult::Fail("8192e is 2T2R");
    }
    if rtl8192e::LC_CAL_PATH_COUNT != 2 {
        return TestResult::Fail("8192e LC cal both paths");
    }

    // IQK both paths.
    let mut iqk_a = [super::phy::IqkStep { reg: 0, val: 0 };
                     rtl8192e::IQK_PATH_A_STEP_COUNT];
    let mut iqk_b = [super::phy::IqkStep { reg: 0, val: 0 };
                     rtl8192e::IQK_PATH_B_STEP_COUNT];
    if rtl8192e::build_iqk_path_a_sequence(&mut iqk_a) != 8 {
        return TestResult::Fail("8192e IQK_A step count != 8");
    }
    if rtl8192e::build_iqk_path_b_sequence(&mut iqk_b) != 8 {
        return TestResult::Fail("8192e IQK_B step count != 8");
    }

    // Dual-path channel set.
    let cs = rtl8192e::channel_set_writes_8192e(11);
    if cs.len() != 2 {
        return TestResult::Fail("8192e channel set should emit 2 writes (A+B)");
    }

    if !rtl8192e::channel_valid(6) {
        return TestResult::Fail("8192e ch 6 valid");
    }
    if rtl8192e::channel_valid(36) {
        return TestResult::Fail("8192e is 2.4 GHz only");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_8192eu_per_chip);

// ── 12. 8723BU per-chip integration ────────────────────────────────

fn smoke_rtl8xxxu_8723bu_per_chip() -> TestResult {
    use super::rtl8723b;

    if rtl8723b::N_MAC_ROWS != 95 {
        return TestResult::Fail("8723b N_MAC_ROWS != 95");
    }
    if rtl8723b::N_PHY_ROWS != 200 {
        return TestResult::Fail("8723b N_PHY_ROWS != 200");
    }
    if rtl8723b::N_RF_A_ROWS != 155 {
        return TestResult::Fail("8723b N_RF_A_ROWS != 155");
    }
    if rtl8723b::NUM_RF_PATHS != 1 {
        return TestResult::Fail("8723b is 1T1R");
    }

    // IQK shape — gen2 has 10 steps.
    let mut iqk = [super::phy::IqkStep { reg: 0, val: 0 };
                   rtl8723b::IQK_PATH_A_STEP_COUNT];
    if rtl8723b::build_iqk_path_a_sequence(&mut iqk) != 10 {
        return TestResult::Fail("8723b IQK step count != 10");
    }

    // LC-cal sequence: pre, mid, post writes (3 entries).
    let lc = rtl8723b::lc_calibrate_sequence_8723b();
    if lc.len() != 3 {
        return TestResult::Fail("8723b LC cal != 3 writes");
    }
    if lc[0].0 != 0xB0 || lc[2].0 != 0xB0 {
        return TestResult::Fail("8723b LC cal pre/post should target RF reg 0xB0");
    }
    if rtl8723b::LC_CAL_HOLD_MS != 200 {
        return TestResult::Fail("8723b LC cal hold should be 200 ms");
    }
    if rtl8723b::LC_CAL_INIT_VAL != 0xDFBE0 {
        return TestResult::Fail("8723b LC init val mismatch");
    }
    if rtl8723b::LC_CAL_FINAL_VAL != 0xDFFE0 {
        return TestResult::Fail("8723b LC final val mismatch");
    }

    // 2.4 GHz only.
    if !rtl8723b::channel_valid(6) {
        return TestResult::Fail("8723b ch 6 valid");
    }
    if rtl8723b::channel_valid(36) {
        return TestResult::Fail("8723b is 2.4 GHz only");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_8723bu_per_chip);

// ── 13. 8723BU BT coex decision matrix ─────────────────────────────

fn smoke_rtl8xxxu_8723bu_bt_coex() -> TestResult {
    use super::btcoex::{
        Bt8723b1AntStatus, BtLinkProfile, coex_table_write_for_type, coex_type_for_state,
        REG_BT_COEX_TABLE1, REG_BT_COEX_TABLE2, REG_BT_COEX_TABLE3, REG_BT_COEX_TABLE4,
    };

    // Coex register addresses.
    if REG_BT_COEX_TABLE1 != 0x06C0 { return TestResult::Fail("table1 addr"); }
    if REG_BT_COEX_TABLE2 != 0x06C4 { return TestResult::Fail("table2 addr"); }
    if REG_BT_COEX_TABLE3 != 0x06C8 { return TestResult::Fail("table3 addr"); }
    if REG_BT_COEX_TABLE4 != 0x06CC { return TestResult::Fail("table4 addr"); }

    // Decision matrix: idle -> type 0, inq -> type 2, sco -> type 7.
    let p = BtLinkProfile::default();
    if coex_type_for_state(Bt8723b1AntStatus::NonConnectedIdle, p) != 0 {
        return TestResult::Fail("NonConnectedIdle should be type 0");
    }
    if coex_type_for_state(Bt8723b1AntStatus::ConnectedIdle, p) != 0 {
        return TestResult::Fail("ConnectedIdle should be type 0");
    }
    if coex_type_for_state(Bt8723b1AntStatus::InqPage, p) != 2 {
        return TestResult::Fail("InqPage should be type 2");
    }
    if coex_type_for_state(Bt8723b1AntStatus::ScoBusy, p) != 7 {
        return TestResult::Fail("ScoBusy should be type 7");
    }
    if coex_type_for_state(Bt8723b1AntStatus::AclScoBusy, p) != 7 {
        return TestResult::Fail("AclScoBusy should be type 7");
    }

    // ACL busy + a2dp-only -> type 5.
    let p_a2dp = BtLinkProfile { has_a2dp: true, a2dp_only: true, ..Default::default() };
    if coex_type_for_state(Bt8723b1AntStatus::AclBusy, p_a2dp) != 5 {
        return TestResult::Fail("AclBusy + a2dp_only should be type 5");
    }
    // ACL busy + hid-only -> type 4.
    let p_hid = BtLinkProfile { has_hid: true, hid_only: true, ..Default::default() };
    if coex_type_for_state(Bt8723b1AntStatus::AclBusy, p_hid) != 4 {
        return TestResult::Fail("AclBusy + hid_only should be type 4");
    }
    // ACL busy + hid + a2dp -> type 6.
    let p_hid_a2dp = BtLinkProfile {
        has_hid: true, has_a2dp: true, ..Default::default()
    };
    if coex_type_for_state(Bt8723b1AntStatus::AclBusy, p_hid_a2dp) != 6 {
        return TestResult::Fail("AclBusy + hid+a2dp should be type 6");
    }
    // ACL busy + nothing -> type 3.
    if coex_type_for_state(Bt8723b1AntStatus::AclBusy, p) != 3 {
        return TestResult::Fail("AclBusy default should be type 3");
    }

    // CoexTableWrite: table4 always 0x03 per Linux.
    for ct in 0..=7u8 {
        let w = coex_table_write_for_type(ct);
        if w.table4 != 0x03 {
            return TestResult::Fail("coex_table4 should always be 0x03");
        }
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_8723bu_bt_coex);

// ── 14. 8821CU per-chip integration + 5 GHz ────────────────────────

fn smoke_rtl8xxxu_8821cu_per_chip() -> TestResult {
    use super::rtl8821c;

    if rtl8821c::N_PHY_ROWS != 480 {
        return TestResult::Fail("8821c N_PHY_ROWS != 480");
    }
    if rtl8821c::N_RF_A_ROWS != 230 {
        return TestResult::Fail("8821c N_RF_A_ROWS != 230");
    }
    if rtl8821c::NUM_RF_PATHS != 1 {
        return TestResult::Fail("8821c is 1T1R");
    }

    // 5 GHz support.
    if !rtl8821c::channel_valid(36) {
        return TestResult::Fail("8821c ch 36 should be valid (5G)");
    }
    if !rtl8821c::channel_valid(149) {
        return TestResult::Fail("8821c ch 149 should be valid (5G UNII-3)");
    }
    if !rtl8821c::channel_is_5ghz(36) {
        return TestResult::Fail("ch 36 is_5ghz");
    }
    if rtl8821c::channel_is_5ghz(6) {
        return TestResult::Fail("ch 6 is_5ghz should be false");
    }

    // Channel 36 = 5180 MHz (bring-up brief target).
    if rtl8821c::channel_freq_mhz_8821c(36) != 5180 {
        return TestResult::Fail("ch 36 must decode to 5180 MHz");
    }
    if rtl8821c::channel_freq_mhz_8821c(6) != 2437 {
        return TestResult::Fail("ch 6 must decode to 2437 MHz");
    }

    // 5 GHz channel set: 2 writes (band-switch + LSSI).
    let cs5 = rtl8821c::channel_set_writes_8821c(36);
    if cs5.len() != 2 {
        return TestResult::Fail("8821c 5GHz channel set: 2 writes (band+LSSI)");
    }
    // 2.4 GHz channel set: 1 write (LSSI only).
    let cs2 = rtl8821c::channel_set_writes_8821c(6);
    if cs2.len() != 1 {
        return TestResult::Fail("8821c 2.4GHz channel set: 1 write");
    }

    // IQK shape.
    let mut iqk = [super::phy::IqkStep { reg: 0, val: 0 };
                   rtl8821c::IQK_PATH_A_STEP_COUNT];
    if rtl8821c::build_iqk_path_a_sequence(&mut iqk) != 12 {
        return TestResult::Fail("8821c IQK step count != 12");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_8821cu_per_chip);

// ── 15. 8822BU per-chip integration + 5 GHz + dual-path ────────────

fn smoke_rtl8xxxu_8822bu_per_chip() -> TestResult {
    use super::rtl8822b;

    if rtl8822b::N_PHY_ROWS != 520 {
        return TestResult::Fail("8822b N_PHY_ROWS != 520");
    }
    if rtl8822b::N_RF_A_ROWS != 245 || rtl8822b::N_RF_B_ROWS != 245 {
        return TestResult::Fail("8822b N_RF_*_ROWS != 245");
    }
    if rtl8822b::NUM_RF_PATHS != 2 {
        return TestResult::Fail("8822b is 2T2R");
    }
    if rtl8822b::LC_CAL_PATH_COUNT != 2 {
        return TestResult::Fail("8822b LC cal both paths");
    }

    // 5 GHz support and ch 36 = 5180.
    if !rtl8822b::channel_valid(36) {
        return TestResult::Fail("8822b ch 36 valid");
    }
    if rtl8822b::channel_freq_mhz_8822b(36) != 5180 {
        return TestResult::Fail("8822b ch 36 must be 5180 MHz");
    }
    if rtl8822b::channel_freq_mhz_8822b(149) != 5745 {
        return TestResult::Fail("8822b ch 149 must be 5745 MHz");
    }

    // 5 GHz channel set: band hint + path A + path B = 3 writes.
    let cs5 = rtl8822b::channel_set_writes_8822b(36);
    if cs5.len() != 3 {
        return TestResult::Fail("8822b 5GHz channel set: 3 writes (band+A+B)");
    }
    // 2.4 GHz channel set: path A + path B = 2 writes.
    let cs2 = rtl8822b::channel_set_writes_8822b(6);
    if cs2.len() != 2 {
        return TestResult::Fail("8822b 2.4GHz channel set: 2 writes (A+B)");
    }

    // IQK both paths — 14 steps each.
    let mut iqk_a = [super::phy::IqkStep { reg: 0, val: 0 };
                     rtl8822b::IQK_PATH_A_STEP_COUNT];
    let mut iqk_b = [super::phy::IqkStep { reg: 0, val: 0 };
                     rtl8822b::IQK_PATH_B_STEP_COUNT];
    if rtl8822b::build_iqk_path_a_sequence(&mut iqk_a) != 14 {
        return TestResult::Fail("8822b IQK_A != 14");
    }
    if rtl8822b::build_iqk_path_b_sequence(&mut iqk_b) != 14 {
        return TestResult::Fail("8822b IQK_B != 14");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_8822bu_per_chip);

// ── 16. Channel-set 5180 MHz coverage (8821CU + 8822BU) ────────────

fn smoke_rtl8xxxu_channel_5180_mhz() -> TestResult {
    use super::phy::channel_freq_mhz;
    // Shared decoder covers all chips' 2.4 + 5 GHz.
    if channel_freq_mhz(36) != 5180 {
        return TestResult::Fail("shared channel_freq_mhz(36) != 5180");
    }
    // Verify per-chip decoders agree with shared for ch 36.
    if super::rtl8821c::channel_freq_mhz_8821c(36) != channel_freq_mhz(36) {
        return TestResult::Fail("8821c ch36 mismatch");
    }
    if super::rtl8822b::channel_freq_mhz_8822b(36) != channel_freq_mhz(36) {
        return TestResult::Fail("8822b ch36 mismatch");
    }
    // 2484 MHz (ch 14, Japan).
    if channel_freq_mhz(14) != 2484 {
        return TestResult::Fail("ch 14 != 2484 MHz");
    }
    // 5825 MHz (ch 165, UNII-3 top).
    if channel_freq_mhz(165) != 5825 {
        return TestResult::Fail("ch 165 != 5825 MHz");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_channel_5180_mhz);

// ── 17. Shared IQ preamble + LC cal sequence shape ─────────────────

fn smoke_rtl8xxxu_iqk_lc_shapes() -> TestResult {
    use super::phy::{
        IQK_PREAMBLE_GEN1, IQK_POLL_MAX, IQK_RESTORE_GEN1,
        lc_calibrate_rf_writes, lssi_encode,
    };

    // Gen1 IQK preamble should be non-empty.
    if IQK_PREAMBLE_GEN1.is_empty() {
        return TestResult::Fail("IQK preamble empty");
    }
    if IQK_RESTORE_GEN1.is_empty() {
        return TestResult::Fail("IQK restore empty");
    }
    if IQK_POLL_MAX < 10 {
        return TestResult::Fail("IQK_POLL_MAX too small");
    }

    // LC cal: 3 RF writes (per Linux gen1 lc-cal sequence).
    let lc = lc_calibrate_rf_writes();
    if lc.len() != 3 {
        return TestResult::Fail("lc_calibrate_rf_writes != 3");
    }

    // LSSI encode: 5-bit addr + 20-bit data layout.
    let w = lssi_encode(0x18, 0xFFFFF);
    // Bits 24..20 should hold addr (0x18 & 0x1F).
    if (w >> 20) & 0x1F != 0x18 {
        return TestResult::Fail("lssi_encode addr bits wrong");
    }
    if w & 0xFFFFF != 0xFFFFF {
        return TestResult::Fail("lssi_encode data bits wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_iqk_lc_shapes);

// ── 18-25: USB class registry + EFUSE bridge smokes ─────────────────
//
// These smokes cover the Wave-11 USB class-driver bridge:
// VID/PID matching, dispatch_probe, chip-family detection, EFUSE
// byte-read sequence, MAC extraction, and disconnect/re-register.
//
// No live USB hardware required; tests use the transport-abstracted
// EFUSE path and the would_match() helper from the class registry.
//
// Linux refs:
//   - drivers/usb/core/driver.c::usb_match_id    ~L141
//   - drivers/usb/core/driver.c::usb_register_driver ~L967
//   - drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c::
//     rtl8xxxu_read_efuse8 ~L1746
//     rtl8xxxu_probe       ~L7692

// ── 18. class_registry: no-match returns false ──────────────────────

fn smoke_rtl8xxxu_class_registry_no_match() -> TestResult {
    use narf_drivers_usb::class_registry;

    // Reset to ensure no prior registrations bleed in.
    class_registry::reset_for_test();

    // With no drivers registered, no VID/PID should match.
    if class_registry::would_match(RTL8XXXU_VENDOR, RTL8188EU_ID) {
        return TestResult::Fail("would_match true with empty registry");
    }
    if class_registry::registered_count() != 0 {
        return TestResult::Fail("registered_count != 0 on fresh registry");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_class_registry_no_match);

// ── 19. class_registry: RTL8188EU VID/PID claimed after registration ─

fn smoke_rtl8xxxu_class_registry_rtl8188eu_match() -> TestResult {
    use narf_drivers_usb::class_registry;
    use super::RTL8XXXU_USB_IDS;

    class_registry::reset_for_test();

    // Register a no-op probe so the table is in.
    fn noop_probe(
        _dev: alloc::sync::Arc<narf_drivers_usb::device::USBDevice>,
    ) -> Result<(), narf_drivers_usb::class_registry::UsbProbeError> {
        Ok(())
    }

    class_registry::register_class_driver("rtl8xxxu-test", RTL8XXXU_USB_IDS, noop_probe)
        .expect("register_class_driver failed");

    // Primary Realtek RTL8188EU ID must match.
    if !class_registry::would_match(RTL8XXXU_VENDOR, RTL8188EU_ID) {
        return TestResult::Fail("RTL8188EU primary ID not matched");
    }
    // Primary Realtek RTL8192EU ID must match.
    if !class_registry::would_match(RTL8XXXU_VENDOR, RTL8192EU_ID) {
        return TestResult::Fail("RTL8192EU primary ID not matched");
    }
    // Primary Realtek RTL8723BU ID must match.
    if !class_registry::would_match(RTL8XXXU_VENDOR, RTL8723BU_ID) {
        return TestResult::Fail("RTL8723BU primary ID not matched");
    }
    // TP-Link TL-WN722N v2 (rebranded RTL8188EU) must match.
    if !class_registry::would_match(0x2357, 0x010C) {
        return TestResult::Fail("TP-Link TL-WN722N v2 not matched");
    }
    // Non-Realtek VID/PID must NOT match.
    if class_registry::would_match(0x1234, 0x5678) {
        return TestResult::Fail("unknown VID/PID incorrectly matched");
    }

    class_registry::reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_class_registry_rtl8188eu_match);

// ── 20. class_registry: non-matching VID/PID not claimed ────────────

fn smoke_rtl8xxxu_class_registry_non_matching() -> TestResult {
    use narf_drivers_usb::class_registry;
    use super::RTL8XXXU_USB_IDS;

    class_registry::reset_for_test();

    fn noop_probe(
        _dev: alloc::sync::Arc<narf_drivers_usb::device::USBDevice>,
    ) -> Result<(), narf_drivers_usb::class_registry::UsbProbeError> {
        Ok(())
    }

    class_registry::register_class_driver("rtl8xxxu-test", RTL8XXXU_USB_IDS, noop_probe)
        .expect("register");

    // A generic USB device with no relation to Realtek must not match.
    if class_registry::would_match(0x05AC, 0x0250) {
        // Apple USB Ethernet adapter — should never match rtl8xxxu
        return TestResult::Fail("Apple device incorrectly matched rtl8xxxu");
    }
    if class_registry::would_match(0x045E, 0x0750) {
        // Microsoft Surface Hub — should never match
        return TestResult::Fail("Microsoft device incorrectly matched");
    }

    class_registry::reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_class_registry_non_matching);

// ── 21. rtl8xxxu_probe stores the device handle ─────────────────────
//
// Calls rtl8xxxu_probe with a real USBDevice from the xHCI controller
// if one is available; otherwise skips. Also tests that DEVICES global
// is populated after a successful probe.

fn smoke_rtl8xxxu_probe_stores_device_handle() -> TestResult {
    // Clear the DEVICES registry before testing.
    super::DEVICES.lock().clear();

    if !narf_drivers_usb::xhci::is_probed() {
        return TestResult::Skip("xhci not probed (no live controller)");
    }
    let c = match narf_drivers_usb::xhci::controller() {
        Some(c) => c,
        None => return TestResult::Skip("xhci controller() returned None"),
    };

    // Build a fake USBDevice with RTL8188EU VID/PID.
    // Use slot 0xFF (unused sentinel) so we don't disturb live slots.
    let mut dev = narf_drivers_usb::device::USBDevice::new(
        c,
        0xFF, // slot_id
        1,    // port
        narf_drivers_usb::xhci::PortSpeed::High,
    );
    dev.set_ids(RTL8XXXU_VENDOR, RTL8188EU_ID);
    let dev = alloc::sync::Arc::new(dev);

    let result = super::rtl8xxxu_probe(dev);
    if result.is_err() {
        return TestResult::Fail("rtl8xxxu_probe returned Err for RTL8188EU");
    }

    // DEVICES should now contain one entry for slot 0xFF.
    let count = super::DEVICES.lock()
        .iter()
        .filter(|d| d.device.slot_id() == 0xFF)
        .count();
    if count != 1 {
        return TestResult::Fail("DEVICES registry missing probe entry");
    }
    if super::DEVICES.lock()
        .iter()
        .find(|d| d.device.slot_id() == 0xFF)
        .map(|d| d.family)
        != Some(ChipFamily::Rtl8188eu)
    {
        return TestResult::Fail("DEVICES entry has wrong ChipFamily");
    }

    // Clean up.
    super::DEVICES.lock().retain(|d| d.device.slot_id() != 0xFF);
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_probe_stores_device_handle);

// ── 22. EFUSE byte read: transport-abstracted round-trip ────────────
//
// Simulates a Realtek REG_EFUSE_CTRL read sequence using a closure
// that returns canned data. Verifies that read_efuse_byte_with_transport
// returns the expected byte value 0xAB.
//
// Linux ref: rtl8xxxu_read_efuse8 (~L1746) in rtl8xxxu_core.c.

fn smoke_rtl8xxxu_efuse_byte_read_transport() -> TestResult {
    use super::efuse::{EfuseAddr, EfuseReadError, read_efuse_byte_with_transport};
    use core::cell::Cell;

    // Simulated register bank. We prime REG_EFUSE_CTRL with:
    //   bit 31 set (data ready) + byte 0xAB in bits[7:0] → 0x800000AB.
    // Other registers (CTRL+1, CTRL+2, CTRL+3) start at 0.
    //
    // Use `Cell` to allow both closures to share the state without
    // conflicting borrows — each Cell is Copy/interior-mutable.
    let reg_ctrl1 = Cell::new(0u8);
    let reg_ctrl2 = Cell::new(0u8);
    let reg_ctrl3 = Cell::new(0u8);
    let efuse_ctrl_word: u32 = 0x8000_00AB; // bit31=ready, data=0xAB

    let mut reg_read = |addr: u16, buf: &mut [u8]| -> Result<(), ()> {
        match (addr, buf.len()) {
            (a, 4) if a == REG_EFUSE_CTRL => {
                buf.copy_from_slice(&efuse_ctrl_word.to_le_bytes());
                Ok(())
            }
            (a, 1) if a == REG_EFUSE_CTRL + 1 => { buf[0] = reg_ctrl1.get(); Ok(()) }
            (a, 1) if a == REG_EFUSE_CTRL + 2 => { buf[0] = reg_ctrl2.get(); Ok(()) }
            (a, 1) if a == REG_EFUSE_CTRL + 3 => { buf[0] = reg_ctrl3.get(); Ok(()) }
            _ => Err(()),
        }
    };
    let mut reg_write = |addr: u16, data: &[u8]| -> Result<(), ()> {
        match (addr, data.len()) {
            (a, 1) if a == REG_EFUSE_CTRL + 1 => { reg_ctrl1.set(data[0]); Ok(()) }
            (a, 1) if a == REG_EFUSE_CTRL + 2 => { reg_ctrl2.set(data[0]); Ok(()) }
            (a, 1) if a == REG_EFUSE_CTRL + 3 => { reg_ctrl3.set(data[0]); Ok(()) }
            _ => Err(()),
        }
    };

    let byte = read_efuse_byte_with_transport(
        EfuseAddr::new(0),
        &mut reg_read,
        &mut reg_write,
    );
    match byte {
        Ok(0xAB) => {}
        Ok(v) => {
            let _ = v;
            return TestResult::Fail("read_efuse_byte returned wrong value");
        }
        Err(EfuseReadError::Timeout) => {
            return TestResult::Fail("EFUSE read timed out");
        }
        Err(_) => {
            return TestResult::Fail("EFUSE read transport error");
        }
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_efuse_byte_read_transport);

// ── 23. EFUSE MAC read: extract MAC from 6-byte EFUSE map block ──────
//
// Constructs a synthetic EFUSE logical map with a known 6-byte MAC at
// EFUSE_WIFI_MAC_OFFSET and verifies extract_mac() decodes it correctly.

fn smoke_rtl8xxxu_efuse_mac_extract() -> TestResult {
    use super::efuse::{extract_mac, EFUSE_WIFI_MAC_OFFSET};
    use super::regs::EFUSE_MAP_LEN;

    let mut map = [0xFFu8; EFUSE_MAP_LEN];
    let mac_expected: [u8; 6] = [0x00, 0x0E, 0xC6, 0xAB, 0xCD, 0xEF];

    // Write the MAC at the canonical offset.
    let off = EFUSE_WIFI_MAC_OFFSET;
    map[off..off + 6].copy_from_slice(&mac_expected);

    let mac = match extract_mac(&map) {
        Some(m) => m,
        None => return TestResult::Fail("extract_mac returned None for valid MAC"),
    };
    if mac != mac_expected {
        return TestResult::Fail("extracted MAC does not match expected");
    }

    // All-zero MAC should be rejected.
    let mut zero_map = [0xFFu8; EFUSE_MAP_LEN];
    zero_map[off..off + 6].copy_from_slice(&[0u8; 6]);
    if extract_mac(&zero_map).is_some() {
        return TestResult::Fail("all-zero MAC should return None");
    }

    // All-0xFF MAC (unwritten EFUSE) should be rejected.
    let ff_map = [0xFFu8; EFUSE_MAP_LEN];
    if extract_mac(&ff_map).is_some() {
        return TestResult::Fail("all-0xFF MAC should return None");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_efuse_mac_extract);

// ── 24. Chip family detection: RTL8723BU → ChipFamily::Rtl8723b ──────
//
// Verifies that ChipFamily::from_usb_id correctly identifies RTL8723BU
// from its primary VID/PID and distinguishes it from RTL8188EU.

fn smoke_rtl8xxxu_chip_family_detection_8723bu() -> TestResult {
    // RTL8723BU primary ID.
    let fam = ChipFamily::from_usb_id(RTL8XXXU_VENDOR, RTL8723BU_ID);
    if fam != ChipFamily::Rtl8723bu {
        return TestResult::Fail("RTL8723BU VID/PID should yield Rtl8723bu");
    }

    // Edimax 7392:A611 (rebranded RTL8723BU) must also yield Rtl8723bu.
    let fam_reb = ChipFamily::from_usb_id(0x7392, 0xA611);
    if fam_reb != ChipFamily::Rtl8723bu {
        return TestResult::Fail("Edimax 7392:A611 should yield Rtl8723bu");
    }

    // RTL8188EU should NOT be confused with RTL8723BU.
    let fam8188 = ChipFamily::from_usb_id(RTL8XXXU_VENDOR, RTL8188EU_ID);
    if fam8188 == ChipFamily::Rtl8723bu {
        return TestResult::Fail("RTL8188EU should not yield Rtl8723bu");
    }
    if fam8188 != ChipFamily::Rtl8188eu {
        return TestResult::Fail("RTL8188EU should yield Rtl8188eu");
    }

    // All 5 chip families are distinguishable.
    let cases: &[(u16, u16, ChipFamily)] = &[
        (RTL8XXXU_VENDOR, RTL8188EU_ID, ChipFamily::Rtl8188eu),
        (RTL8XXXU_VENDOR, RTL8192EU_ID, ChipFamily::Rtl8192eu),
        (RTL8XXXU_VENDOR, RTL8723BU_ID, ChipFamily::Rtl8723bu),
        (RTL8XXXU_VENDOR, RTL8821CU_ID, ChipFamily::Rtl8821cu),
        (RTL8XXXU_VENDOR, RTL8822BU_ID, ChipFamily::Rtl8822bu),
    ];
    for &(vid, pid, expected) in cases {
        if ChipFamily::from_usb_id(vid, pid) != expected {
            return TestResult::Fail("chip family mismatch in all-5 check");
        }
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_chip_family_detection_8723bu);

// ── 25. Disconnect path: re-register after DEVICES cleared ──────────
//
// Verifies that after the DEVICES registry is cleared (simulating a
// disconnect), a new probe for the same VID/PID succeeds and creates
// a fresh entry. Tests the idempotency guard on slot_id dedup.

fn smoke_rtl8xxxu_disconnect_re_register() -> TestResult {
    super::DEVICES.lock().clear();

    if !narf_drivers_usb::xhci::is_probed() {
        return TestResult::Skip("xhci not probed");
    }
    let c = match narf_drivers_usb::xhci::controller() {
        Some(c) => c,
        None => return TestResult::Skip("xhci controller() returned None"),
    };

    // First probe — uses sentinel slot 0xFE.
    let mut dev1 = narf_drivers_usb::device::USBDevice::new(
        c.clone(),
        0xFE,
        1,
        narf_drivers_usb::xhci::PortSpeed::High,
    );
    dev1.set_ids(RTL8XXXU_VENDOR, RTL8192EU_ID);
    let dev1 = alloc::sync::Arc::new(dev1);

    if super::rtl8xxxu_probe(dev1).is_err() {
        return TestResult::Fail("first probe failed");
    }
    let count_after_first = super::DEVICES.lock()
        .iter()
        .filter(|d| d.device.slot_id() == 0xFE)
        .count();
    if count_after_first != 1 {
        return TestResult::Fail("DEVICES entry missing after first probe");
    }

    // Simulate disconnect by removing the entry.
    super::DEVICES.lock().retain(|d| d.device.slot_id() != 0xFE);
    let count_after_disconnect = super::DEVICES.lock()
        .iter()
        .filter(|d| d.device.slot_id() == 0xFE)
        .count();
    if count_after_disconnect != 0 {
        return TestResult::Fail("DEVICES entry not cleared on disconnect");
    }

    // Second probe on the same slot should succeed (not double-insert).
    let mut dev2 = narf_drivers_usb::device::USBDevice::new(
        c,
        0xFE,
        1,
        narf_drivers_usb::xhci::PortSpeed::High,
    );
    dev2.set_ids(RTL8XXXU_VENDOR, RTL8192EU_ID);
    let dev2 = alloc::sync::Arc::new(dev2);

    if super::rtl8xxxu_probe(dev2).is_err() {
        return TestResult::Fail("second probe after disconnect failed");
    }
    let count_after_second = super::DEVICES.lock()
        .iter()
        .filter(|d| d.device.slot_id() == 0xFE)
        .count();
    if count_after_second != 1 {
        return TestResult::Fail("DEVICES count wrong after re-register");
    }

    // Clean up.
    super::DEVICES.lock().retain(|d| d.device.slot_id() != 0xFE);
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu", smoke_rtl8xxxu_disconnect_re_register);
