// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the BE EFUSE protocol. The fake BAR is scripted
//! from the Linux `efuse_be.c` / `rtw8922a.c` text: expected register
//! sequences and logical-map contents are derived from that text, never
//! from the production code under test.

use super::chip_8922a::{self, EfuseBlockKind};
use super::efuse::Io;
use super::efuse_be::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs8: Vec<(u64, u8)>,
    regs16: Vec<(u64, u16)>,
    regs32: Vec<(u64, u32)>,
    ctrl1_data: Vec<u32>,
    rdy: bool,
    pwr_state: u32,
    writes: Vec<(u64, u8, u32)>,
    delays: Vec<u64>,
}

impl Fake {
    fn new() -> Self {
        Self {
            regs8: Vec::new(),
            regs16: Vec::new(),
            regs32: Vec::new(),
            ctrl1_data: Vec::new(),
            rdy: true,
            // (raw & WHOLE_SYS_PWR_STE_MASK) == SYS_ACT << 16.
            pwr_state: 0x220 << 16,
            writes: Vec::new(),
            delays: Vec::new(),
        }
    }
    fn set16(&mut self, addr: u64, val: u16) {
        if let Some(slot) = self.regs16.iter_mut().find(|(a, _)| *a == addr) {
            slot.1 = val;
        } else {
            self.regs16.push((addr, val));
        }
    }
    fn set32(&mut self, addr: u64, val: u32) {
        if let Some(slot) = self.regs32.iter_mut().find(|(a, _)| *a == addr) {
            slot.1 = val;
        } else {
            self.regs32.push((addr, val));
        }
    }
    fn get32(&self, addr: u64) -> u32 {
        self.regs32
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }
}

impl Io for Fake {
    fn read8(&mut self, addr: u64) -> u8 {
        self.regs8
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }
    fn write8(&mut self, addr: u64, val: u8) {
        if let Some(slot) = self.regs8.iter_mut().find(|(a, _)| *a == addr) {
            slot.1 = val;
        } else {
            self.regs8.push((addr, val));
        }
        self.writes.push((addr, 1, val as u32));
    }
    fn read16(&mut self, addr: u64) -> u16 {
        self.regs16
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }
    fn write16(&mut self, addr: u64, val: u16) {
        self.set16(addr, val);
        self.writes.push((addr, 2, val as u32));
    }
    fn read32(&mut self, addr: u64) -> u32 {
        if addr == EFUSE_CTRL as u64 {
            let mut v = self.get32(addr);
            if self.rdy {
                v |= EF_RDY;
            }
            return v;
        }
        if addr == EFUSE_CTRL_1_V1 as u64 {
            if self.ctrl1_data.is_empty() {
                return 0;
            }
            return self.ctrl1_data.remove(0);
        }
        if addr == IC_PWR_STATE as u64 {
            return self.pwr_state;
        }
        self.get32(addr)
    }
    fn write32(&mut self, addr: u64, val: u32) {
        self.set32(addr, val);
        self.writes.push((addr, 4, val));
    }
    fn delay_us(&mut self, us: u64) {
        self.delays.push(us);
    }
}

/// The exact power-cut + dump write sequence for one word, from
/// `efuse_be.c:32..51` (enable) and `efuse_be.c:53..71` (disable).
fn expect_ddv_sequence(fake: &Fake, addr: u32) -> bool {
    fake.writes
        == [
            (PMC_DBG_CTRL2 as u64, 1, 0x04),
            (SYS_ISO_CTRL as u64, 2, 0x4000),
            (SYS_ISO_CTRL as u64, 2, 0xC000),
            (SYS_ISO_CTRL as u64, 2, 0xC000),
            (EFUSE_CTRL_2_V1 as u64, 4, 0x80000),
            (EFUSE_CTRL as u64, 4, addr),
            (SYS_ISO_CTRL as u64, 2, 0xC100),
            (SYS_ISO_CTRL as u64, 2, 0x4100),
            (SYS_ISO_CTRL as u64, 2, 0x0100),
            (PMC_DBG_CTRL2 as u64, 1, 0x00),
            (EFUSE_CTRL_2_V1 as u64, 4, 0x00),
        ]
        && fake.delays == [1000, 1000]
}

fn smoke_rtw89_be_efuse_ddv_dump() -> TestResult {
    // Happy path: one word, ISO sequence present (not a CAV cut).
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0x1122_3344);
    let mut out = [0u8; 4];
    if dump_physical_ddv(&mut fake, false, 0x100, &mut out).is_err() {
        return TestResult::Fail("BE DDV dump failed on a ready device");
    }
    if out != [0x44, 0x33, 0x22, 0x11] {
        return TestResult::Fail("BE DDV dump word not little-endian stored");
    }
    if !expect_ddv_sequence(&fake, 0x100) {
        return TestResult::Fail("BE DDV power-cut/dump write sequence wrong");
    }
    // CAV cut: the ISO steps must vanish entirely (masking-defeating
    // twin of the case above — a fake ignoring the cut flag fails one
    // of the two).
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0xAABB_CCDD);
    let mut out = [0u8; 4];
    if dump_physical_ddv(&mut fake, true, 0x104, &mut out).is_err() {
        return TestResult::Fail("BE DDV dump failed for a CAV cut");
    }
    if out != [0xDD, 0xCC, 0xBB, 0xAA] {
        return TestResult::Fail("BE DDV CAV dump word wrong");
    }
    if fake.writes
        != [
            (PMC_DBG_CTRL2 as u64, 1, 0x04),
            (EFUSE_CTRL_2_V1 as u64, 4, 0x80000),
            (EFUSE_CTRL as u64, 4, 0x104),
            (PMC_DBG_CTRL2 as u64, 1, 0x00),
            (EFUSE_CTRL_2_V1 as u64, 4, 0x00),
        ]
        || !fake.delays.is_empty()
    {
        return TestResult::Fail("BE DDV CAV dump must skip the ISO sequence");
    }
    // Unaligned address or size is rejected before any register write.
    let mut fake = Fake::new();
    let mut out = [0u8; 4];
    if dump_physical_ddv(&mut fake, false, 0x102, &mut out) != Err(BeEfuseError::Unaligned)
        || !fake.writes.is_empty()
    {
        return TestResult::Fail("BE DDV dump accepted an unaligned address");
    }
    // RDY never set: Busy, and power-cut is left enabled (no disable
    // writes after the failed address write), as in Linux.
    let mut fake = Fake::new();
    fake.rdy = false;
    let mut out = [0u8; 4];
    if dump_physical_ddv(&mut fake, false, 0x100, &mut out) != Err(BeEfuseError::Busy) {
        return TestResult::Fail("BE DDV dump did not time out on RDY");
    }
    if fake.delays.len() != 1 + 1_000_000 {
        return TestResult::Fail("BE DDV RDY poll must tick 1 µs to a 1 s timeout");
    }
    if fake.writes.contains(&(PMC_DBG_CTRL2 as u64, 1, 0x00)) {
        return TestResult::Fail("BE DDV timeout must leave power-cut enabled");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_efuse_ddv_dump);

fn smoke_rtw89_be_efuse_convert_state() -> TestResult {
    // Idle: set the BT-disable bit, no poll.
    let mut fake = Fake::new();
    if convert_state(&mut fake, true).is_err() {
        return TestResult::Fail("BE convert to idle failed");
    }
    if fake.writes != [(WL_BT_PWR_CTRL as u64, 4, 0x10000)] || !fake.delays.is_empty() {
        return TestResult::Fail("BE convert to idle must only set BT_DISN_EN");
    }
    // Active: clear the bit, power state already SYS_ACT → no delays.
    let mut fake = Fake::new();
    if convert_state(&mut fake, false).is_err() {
        return TestResult::Fail("BE convert to active failed on SYS_ACT");
    }
    if fake.writes != [(WL_BT_PWR_CTRL as u64, 4, 0x00)] || !fake.delays.is_empty() {
        return TestResult::Fail("BE convert to active must not poll on SYS_ACT");
    }
    // Power state never SYS_ACT: 100 × 50 µs ticks, then timeout.
    let mut fake = Fake::new();
    fake.pwr_state = 0;
    if convert_state(&mut fake, false) != Err(BeEfuseError::PowerStateTimeout) {
        return TestResult::Fail("BE convert to active did not time out");
    }
    if fake.delays.len() != 100 || fake.delays.iter().any(|d| *d != 50) {
        return TestResult::Fail("BE power-state poll must tick 50 µs × 100");
    }
    // The wrapper ignores a convert failure (warn-and-continue) but
    // still runs the dump; an empty dump returns Ok with no IO at all.
    let mut fake = Fake::new();
    let mut out = [0u8; 0];
    if dump_physical(&mut fake, false, 0x100, &mut out).is_err() || !fake.writes.is_empty() {
        return TestResult::Fail("BE empty dump must be a no-op");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_efuse_convert_state);

/// Build a physical map (0x1300 bytes) whose RF block (page 1) carries
/// a country record, a decoy other-page record, and a word-enable
/// skip record, per the `efuse_be.c` header format.
fn build_phy_map() -> [u8; 0x1300] {
    let mut phy = [0xFF; 0x1300];
    let mut idx = 4usize;
    // Header: page 1, blk 0, word_en 0 → 8 bytes land at RF log 0..8.
    phy[idx..idx + 3].copy_from_slice(&[0x02, 0x00, 0x00]);
    idx += 3;
    phy[idx..idx + 8].copy_from_slice(b"US\xAA\xBB\xCC\xDD\xEE\xFF");
    idx += 8;
    // Header: page 2, blk 0, word_en 0 → consumed but NOT for RF.
    phy[idx..idx + 3].copy_from_slice(&[0x04, 0x00, 0x00]);
    idx += 3;
    phy[idx..idx + 8].copy_from_slice(b"DECOY!!!");
    idx += 8;
    // Header: page 1, blk 1, word_en 0b0001 → word 0 skipped (no bytes
    // consumed), words 1..3 land at RF log 10..16.
    phy[idx..idx + 3].copy_from_slice(&[0x02, 0x00, 0x11]);
    idx += 3;
    phy[idx..idx + 6].copy_from_slice(b"W12345");
    idx += 6;
    // Header: page 1, blk 23, word_en 0 → 8 bytes at RF log 184..192;
    // xtal_k is the second byte of word 0 (log 185).
    phy[idx..idx + 3].copy_from_slice(&[0x02, 0x01, 0x70]);
    idx += 3;
    phy[idx..idx + 8].copy_from_slice(&[0x11, 0x5A, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    idx += 8;
    // Header: page 1, blk 25, word_en 0 → 8 bytes at RF log 200..208;
    // rfe_type is the first byte of word 1 (log 202 =
    // `block_idx_to_logical_idx_be(25, 1)`, efuse_be.c).
    phy[idx..idx + 3].copy_from_slice(&[0x02, 0x01, 0x90]);
    idx += 3;
    phy[idx..idx + 8].copy_from_slice(&[0x21, 0x22, 0x77, 0x24, 0x25, 0x26, 0x27, 0x28]);
    idx += 8;
    // Terminator: any 0xFF header byte stops the parse.
    phy[idx] = 0xFF;
    phy
}

fn smoke_rtw89_be_efuse_logical_parse() -> TestResult {
    let phy = build_phy_map();
    let mut rf_log = [0u8; 0x240];
    if parse_logical_block(
        &phy,
        &chip_8922a::EFUSE_BLOCKS[1],
        EfuseBlockKind::Rf,
        chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
        &mut rf_log,
    )
    .is_err()
    {
        return TestResult::Fail("BE logical parse failed");
    }
    if rf_log[0] != b'U' || rf_log[1] != b'S' {
        return TestResult::Fail("BE logical parse country record wrong");
    }
    if rf_log[2..8] != [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] {
        return TestResult::Fail("BE logical parse first block body wrong");
    }
    // The page-2 decoy must not leak into the page-1 log.
    if rf_log[8..10] != [0xFF, 0xFF] || rf_log[10..16] != *b"W12345" {
        return TestResult::Fail("BE logical parse word-enable skip or page filter wrong");
    }
    if rf_log[185] != 0x5A {
        return TestResult::Fail("BE logical parse xtal_k position wrong");
    }
    if rf_log[202] != 0x77 {
        return TestResult::Fail("BE logical parse rfe_type position wrong");
    }
    if rf_log[16..184].iter().any(|b| *b != 0xFF) {
        return TestResult::Fail("BE logical parse touched unwritten log bytes");
    }
    // The same map parsed for the PCIe HCI_DIG block (page 2) must
    // contain ONLY the decoy record.
    let mut hci_log = [0u8; 0x4800];
    if parse_logical_block(
        &phy,
        &chip_8922a::EFUSE_BLOCKS[2],
        EfuseBlockKind::HciDigPcieSdio,
        chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
        &mut hci_log,
    )
    .is_err()
    {
        return TestResult::Fail("BE HCI_DIG logical parse failed");
    }
    if hci_log[0..8] != *b"DECOY!!!" || hci_log[8..16].iter().any(|b| *b != 0xFF) {
        return TestResult::Fail("BE HCI_DIG parse leaked page-1 records");
    }
    // `blk_idx >= RTW89_EFUSE_MAX_BLOCK_SIZE >> 3` (0x2000) cannot
    // fire on the 3-byte header: EFUSE_HDR_OFFSET_MASK is 13 bits
    // (max 0x1FFF), and the 0xFF bytes a larger value would need end
    // the parse first (efuse_be.c). A lone other-page record is
    // consumed and leaves the RF log untouched.
    let mut phy_bad = [0xFF; 0x1300];
    phy_bad[4..7].copy_from_slice(&[0x04, 0x00, 0x00]);
    let mut log = [0u8; 0x240];
    if parse_logical_block(
        &phy_bad,
        &chip_8922a::EFUSE_BLOCKS[1],
        EfuseBlockKind::Rf,
        chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
        &mut log,
    ) != Ok(())
        || log.iter().any(|b| *b != 0xFF)
    {
        return TestResult::Fail("BE logical parse wrote another page's record");
    }
    // A map too short for its header is truncated, not read OOB.
    let short = [0xFF; 5];
    if parse_logical_block(
        &short,
        &chip_8922a::EFUSE_BLOCKS[1],
        EfuseBlockKind::Rf,
        chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
        &mut log,
    ) != Err(BeEfuseError::Truncated)
    {
        return TestResult::Fail("BE logical parse read past a short map");
    }
    // ADIE 2-byte headers: blk 1, word_en 0 → 8 bytes at log 8..16.
    let mut phy_adie = [0xFF; 0x1300];
    phy_adie[4..6].copy_from_slice(&[0x00, 0x10]);
    phy_adie[6..14].copy_from_slice(b"ADIE1234");
    phy_adie[14] = 0xFF;
    let mut adie_log = [0u8; 0x10];
    if parse_logical_block(
        &phy_adie,
        &chip_8922a::EFUSE_BLOCKS[7],
        EfuseBlockKind::Adie,
        chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
        &mut adie_log,
    )
    .is_err()
        || adie_log[0..8] != [0xFF; 8]
        || adie_log[8..16] != *b"ADIE1234"
    {
        return TestResult::Fail("BE ADIE 2-byte header parse wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_efuse_logical_parse);

fn smoke_rtw89_be_efuse_readers() -> TestResult {
    // ECV: cut version 3 in the high nibble of buff[2] (bits 23..16
    // of the little-endian dump word).
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0x0030_0000);
    if read_ecv(&mut fake, false) != Ok(3) {
        return TestResult::Fail("BE ECV decode wrong");
    }
    // ECV 0xF means no cut version stored.
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0x00F0_0000);
    if read_ecv(&mut fake, false) != Err(BeEfuseError::NotPresent) {
        return TestResult::Fail("BE ECV must report NotPresent for 0xF");
    }
    // Thermal K: sign bit set, value 0xA5 → -165.
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0x0000_01A5);
    if read_thermal_k(&mut fake, false) != Ok(-165) {
        return TestResult::Fail("BE thermal K signed decode wrong");
    }
    // Thermal K: no sign, value 0x2A → 42.
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0x0000_002A);
    if read_thermal_k(&mut fake, false) != Ok(42) {
        return TestResult::Fail("BE thermal K unsigned decode wrong");
    }
    // Thermal K: VALID bit set → no K stored.
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0x0000_0200);
    if read_thermal_k(&mut fake, false) != Err(BeEfuseError::NotPresent) {
        return TestResult::Fail("BE thermal K must report NotPresent when VALID");
    }
    // Secure: default cryp-sel → not secure, no magnitude.
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0xFFFF_0000);
    let sec = match read_secure(&mut fake, false) {
        Ok(sec) => sec,
        Err(_) => return TestResult::Fail("BE secure read failed on default"),
    };
    if sec.secure_boot || sec.sb_sel_mgn.is_some() {
        return TestResult::Fail("BE default cryp-sel must be insecure");
    }
    // Secure: valid index 1 + WinlinInbox MSS → secure.
    // cryp_sel 0xE17E: form 0x7E palindrome with zero pair at index 0,
    // idx byte 0xE1 (nibbles XOR to 0xF) → index 1 → 0xC000180.
    // b1 0x6C: dev 0xC, cust0 0x6; b2 0x03: cust1 0, key 0x3.
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0xE17E_036C);
    let sec = match read_secure(&mut fake, false) {
        Ok(sec) => sec,
        Err(_) => return TestResult::Fail("BE secure read failed on valid MSS"),
    };
    if !sec.secure_boot
        || sec.sb_sel_mgn != Some(0xC000180)
        || sec.mss_dev_type != Some(MssDevType::WinlinInbox)
        || sec.mss_cust_idx != 25
        || sec.mss_key_num != 12
    {
        return TestResult::Fail("BE secure MSS decode wrong");
    }
    // Secure: valid index 0 + same MSS → secure, magnitude 0x8000100.
    // cryp_sel 0xF07E: form 0x7E palindrome with zero pair at index 0,
    // idx byte 0xF0 (nibbles XOR to 0xF) → index 0 → 0x8000100.
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0xF07E_036C);
    let sec = match read_secure(&mut fake, false) {
        Ok(sec) => sec,
        Err(_) => return TestResult::Fail("BE secure read failed on index 0"),
    };
    if !sec.secure_boot
        || sec.sb_sel_mgn != Some(0x8000100)
        || sec.mss_dev_type != Some(MssDevType::WinlinInbox)
        || sec.mss_cust_idx != 25
        || sec.mss_key_num != 12
    {
        return TestResult::Fail("BE secure index-0 decode wrong");
    }
    // The Linux-mapped device indices (efuse.c get_mss_dev_type_idx):
    // raw nibbles 0xC/0xA/0x9/0x6 map to 0/1/2/3, default 0xF stays 0xF.
    if MssDevType::WinlinInbox.index() != 0
        || MssDevType::NonlinInboxNonCob.index() != 1
        || MssDevType::NonlinInboxCob.index() != 2
        || MssDevType::NonwinInbox.index() != 3
        || MssDevType::Default.index() != 15
    {
        return TestResult::Fail("BE MSS device index is not the Linux mapping");
    }
    // Secure: valid index but unknown dev type → insecure, yet the
    // magnitude stays set (Linux sets it before the MSS decode).
    let mut fake = Fake::new();
    fake.ctrl1_data.push(0xE17E_0305);
    let sec = match read_secure(&mut fake, false) {
        Ok(sec) => sec,
        Err(_) => return TestResult::Fail("BE secure read failed on bad dev type"),
    };
    if sec.secure_boot || sec.sb_sel_mgn != Some(0xC000180) {
        return TestResult::Fail("BE bad dev type must stay insecure with magnitude set");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_efuse_readers);

fn smoke_rtw89_be_factory_read() -> TestResult {
    let phy = build_phy_map();
    let mut fake = Fake::new();
    // Main physical dump: 1216 words, in order.
    for chunk in phy.chunks(4) {
        fake.ctrl1_data
            .push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    // PHY-cap dump: 14 words of 0x5C.
    for _ in 0..14 {
        fake.ctrl1_data.push(0x5C5C_5C5C);
    }
    // ECV dump: cut version 2 (buff[2] = 0x20).
    fake.ctrl1_data.push(0x0020_0000);
    // Thermal dump: 42, unsigned.
    fake.ctrl1_data.push(0x0000_002A);
    // Secure window: default cryp-sel → secure boot off.
    fake.ctrl1_data.push(0xFFFF_0000);
    // MAC from PCIe BAR registers (LE per u16).
    fake.set16(MAC_ADDR_PCIE as u64, 0x2211);
    fake.set16((MAC_ADDR_PCIE + 2) as u64, 0x4433);
    fake.set16((MAC_ADDR_PCIE + 4) as u64, 0x6655);
    let factory = match BeFactory::read(&mut fake, false, Hci::Pcie) {
        Ok(factory) => factory,
        Err(_) => return TestResult::Fail("BE factory read failed"),
    };
    if factory.mac != [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] {
        return TestResult::Fail("BE factory MAC from BAR registers wrong");
    }
    if factory.country != *b"US" || factory.xtal_cap != 0x5A || factory.rfe_type != 0x77 {
        return TestResult::Fail("BE factory RF fields wrong");
    }
    if factory.phycap != [0x5C; 0x38] {
        return TestResult::Fail("BE factory PHY-cap window wrong");
    }
    if factory.cv != Some(2) || factory.thermal_k != Some(42) {
        return TestResult::Fail("BE factory cut/thermal wrong");
    }
    if factory.secure != SecureInfo::disabled() {
        return TestResult::Fail("BE factory secure state wrong on default cryp-sel");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_factory_read);

fn smoke_rtw89_be_factory_power_trim() -> TestResult {
    let factory = |phycap: [u8; chip_8922a::PHYCAP_SIZE]| BeFactory {
        mac: [0; 6],
        rfe_type: 0,
        xtal_cap: 0,
        country: [0; 2],
        phycap,
        cv: None,
        thermal_k: None,
        secure: SecureInfo::disabled(),
    };
    let mut cap = [0u8; chip_8922a::PHYCAP_SIZE];
    // Thermal: path A 0x45 = +5 (BIT(6) set); path B 0x03 = -3.
    cap[6] = 0x45;
    cap[0x33] = 0x03;
    // PA bias: A 0x21 (2G 1, 5G 2), B 0x43; pad bias: A 0x54, B 0x76.
    cap[7] = 0x21;
    cap[0x34] = 0x43;
    cap[8] = 0x54;
    cap[0x35] = 0x76;
    // phycap[0] programmed (not 0xFF): the PA/pad gate is open.
    cap[0] = 0x00;
    let trim = factory(cap).power_trim();
    if trim
        != (PowerTrim {
            thermal: [5, -3],
            pg_thermal: true,
            pa_bias: [0x21, 0x43],
            pad_bias: [0x54, 0x76],
            pg_pa_pad: true,
        })
    {
        return TestResult::Fail("8922A power trim parse differs from rtw8922a_phycap_parsing_*");
    }
    // Unprogrammed path-B thermal: trim 0, pg false, path A kept.
    let mut cap2 = cap;
    cap2[0x33] = 0xFF;
    let trim2 = factory(cap2).power_trim();
    if trim2.thermal != [5, 0] || trim2.pg_thermal {
        return TestResult::Fail("8922A unprogrammed thermal path did not stop the parse");
    }
    // Unprogrammed phycap[0]: the PA/pad gate closes, bytes still parsed.
    let mut cap3 = cap;
    cap3[0] = 0xFF;
    let trim3 = factory(cap3).power_trim();
    if trim3.pg_pa_pad || trim3.pa_bias != [0x21, 0x43] || trim3.pad_bias != [0x54, 0x76] {
        return TestResult::Fail("8922A PA/pad programmed flag differs");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_factory_power_trim);
