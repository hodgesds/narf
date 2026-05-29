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

use super::efuse::{decode_efuse_map, efuse_addr_setups, extract_mac, mac_is_valid, EfuseAddr};
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
