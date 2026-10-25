//! Sparse-map and traced-register regressions for the live probe identity path.

use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::efuse::{decode_map, read_factory_with, read_mac_with, EfuseError, EfuseIo};
use super::regs::*;

#[derive(Debug)]
struct FakeEfuse {
    physical: [u8; 1024],
    bank: u32,
    analog_ldo: u8,
    control: u32,
    pending_reads: usize,
    writes: Vec<(u64, u32)>,
    stalled: bool,
}

impl FakeEfuse {
    fn new(records: &[u8]) -> Self {
        let mut physical = [0xff; 1024];
        physical[..records.len()].copy_from_slice(records);
        Self {
            physical,
            bank: 0x8000_03a5,
            analog_ldo: 0xb5,
            control: 0xa400_111b,
            pending_reads: 0,
            writes: Vec::new(),
            stalled: false,
        }
    }
}

impl EfuseIo for FakeEfuse {
    fn read8(&mut self, addr: u64) -> u8 {
        match addr {
            REG_ANAPARLDO_POW_MAC => self.analog_ldo,
            a if a == REG_LDO_EFUSE_CTRL + 3 => (self.bank >> 24) as u8,
            _ => 0xff,
        }
    }
    fn write8(&mut self, addr: u64, value: u8) {
        self.writes.push((addr, value as u32));
        if addr == REG_ANAPARLDO_POW_MAC {
            self.analog_ldo = value;
        } else if addr == REG_LDO_EFUSE_CTRL + 3 {
            self.bank = (self.bank & 0x00ff_ffff) | ((value as u32) << 24);
        }
    }
    fn read32(&mut self, addr: u64) -> u32 {
        if addr == REG_LDO_EFUSE_CTRL {
            return self.bank;
        }
        if self.pending_reads == 0 {
            return self.control;
        }
        self.pending_reads += 1;
        // First sample is busy, with deliberately incorrect data. The
        // second sets the flag and returns the requested physical byte.
        if self.pending_reads == 2 || self.stalled {
            return (self.control & !EFUSE_CTRL_VALID) | 0x42;
        }
        let offset = ((self.control >> EFUSE_CTRL_ADDR_SHIFT) & EFUSE_CTRL_ADDR_MASK) as usize;
        self.control | EFUSE_CTRL_VALID | self.physical[offset] as u32
    }
    fn write32(&mut self, addr: u64, value: u32) {
        self.writes.push((addr, value));
        if addr == REG_LDO_EFUSE_CTRL {
            self.bank = value;
        } else {
            self.control = value;
            self.pending_reads = 1;
        }
    }
}

include!("factory/golden.rs");
include!("factory/rtl8821c_golden.rs");

fn smoke_rtw8821ce_retained_factory_uses_actual_packed_one_path_geometry() -> TestResult {
    let mut logical = [255; 768];
    for (offset, length) in LINUX_8821C_FACTORY {
        for (i, byte) in logical[*offset..offset + length].iter_mut().enumerate() {
            *byte = (*offset as u8).wrapping_add(i as u8);
        }
    }
    logical[0xca] = 0xa4;
    logical[0xd0..0xd6].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    let records = sparse_factory(&logical);
    let mut io = FakeEfuse::new(&records);
    let factory = match super::efuse::read_factory8821c_with(&mut io, RTL_DEV_8821CE) {
        Ok(factory) => factory,
        Err(_) => return TestResult::Fail("8821C retained original factory map rejected"),
    };
    if factory.logical() != &logical[..512]
        || factory.mac() != [2, 4, 6, 8, 10, 12]
        || factory.raw_rfe() != 0xa4
        || factory.rfe() != 4
        || factory.package() != 1
        || factory.thermal() != logical[LINUX_8821C_FACTORY[3].0]
        || factory.crystal() != logical[LINUX_8821C_FACTORY[2].0]
        || factory.country() != logical[0xcb..0xcd]
        || factory.channel_plan() != logical[0xb8]
        || factory.board_option() != logical[0xc1]
        || factory.bt_setting() != logical[0xc3]
        || factory.power_path(4).is_some()
    {
        return TestResult::Fail("8821C factory offsets/package extraction diverged from Linux");
    }
    for path in 0..4 {
        let at = 0x10 + path * 42;
        if factory.power_path(path as u8) != Some(&logical[at..at + 42]) {
            return TestResult::Fail("8821C raw factory power path was substituted/defaulted");
        }
    }
    if io
        .writes
        .iter()
        .filter(|(reg, _)| *reg == REG_EFUSE_CTRL)
        .count()
        != 416
    {
        return TestResult::Fail("8821C read C22 trims or reread its factory map");
    }
    let before = io.writes.len();
    if !matches!(
        super::efuse::read_factory8821c_with(&mut io, RTL_DEV_8822CE),
        Err(EfuseError::UnsupportedChip)
    ) || io.writes.len() != before
    {
        return TestResult::Fail("8821C factory type accepted another chip before validation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_retained_factory_uses_actual_packed_one_path_geometry
);
fn sparse_factory(logical: &[u8; 768]) -> Vec<u8> {
    let mut records = Vec::new();
    for (block, bytes) in logical.chunks_exact(8).enumerate() {
        let mut disabled = 0u8;
        for word in 0..4 {
            if bytes[word * 2..word * 2 + 2] == [255; 2] {
                disabled |= 1 << word;
            }
        }
        if disabled == 15 {
            continue;
        }
        if block < 16 {
            records.push((block as u8) << 4 | disabled);
        } else {
            records.push(((block as u8 & 7) << 5) | 15);
            records.push(((block as u8 & 0x78) << 1) | disabled);
        }
        for word in 0..4 {
            if disabled & (1 << word) == 0 {
                records.extend_from_slice(&bytes[word * 2..word * 2 + 2]);
            }
        }
    }
    records.push(255);
    records
}
fn smoke_rtw8822ce_retains_same_physical_factory_map_with_linux_packed_geometry() -> TestResult {
    let mut logical = [255; 768];
    let (power, length) = LINUX_FACTORY[0];
    if LINUX_POWER_PATH * 4 != length {
        return TestResult::Fail("actual Linux factory power-path geometry");
    }
    for (i, byte) in logical[power..power + length].iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(13).wrapping_add(7);
    }
    for (index, value) in [
        (1, 6),
        (2, 0xb3),
        (3, 0x42),
        (4, 0x17),
        (5, 5),
        (7, 25),
        (8, 27),
    ] {
        logical[LINUX_FACTORY[index].0] = value;
    }
    let country = LINUX_FACTORY[6].0;
    logical[country..country + 2].copy_from_slice(b"US");
    let mac = LINUX_FACTORY[9].0;
    logical[mac..mac + 6].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    let records = sparse_factory(&logical);
    if records.len() > 388 {
        return TestResult::Fail("factory fixture exceeded actual unprotected OTP");
    }
    let mut io = FakeEfuse::new(&records);
    // A plausible protected-tail record cannot override retained RFE data.
    io.physical[388..394].copy_from_slice(&[0x2f, 0x1e, 0x99, 0x99, 0xff, 0xff]);
    let expected_trims =
        core::array::from_fn::<_, 19, _>(|i| (i as u8).wrapping_mul(19).wrapping_add(3));
    for (address, value) in LINUX_TRIM_ADDRESSES.into_iter().zip(expected_trims) {
        io.physical[usize::from(address)] = value;
    }
    let factory = match read_factory_with(&mut io, RTL_DEV_8822CE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("factory source read/decode failed"),
    };
    if factory.logical() != &logical
        || super::efuse::TRIM_ADDRESSES != LINUX_TRIM_ADDRESSES
        || factory.trims() != &expected_trims
        || factory.mac() != [2, 4, 6, 8, 10, 12]
        || factory.channel_plan() != 6
        || factory.crystal() != 0xb3
        || factory.board_option() != 0x42
        || factory.bt_setting() != 0x17
        || factory.rfe() != 5
        || factory.country() != *b"US"
        || factory.thermal() != [25, 27]
        || (0..4).any(|path| {
            let at = power + usize::from(path) * LINUX_POWER_PATH;
            factory.power_path(path) != Some(&logical[at..at + LINUX_POWER_PATH])
        })
        || factory.power_path(4).is_some()
    {
        return TestResult::Fail("retained factory fields did not match actual packed Linux map");
    }
    let mut erased = FakeEfuse::new(&sparse_factory(&{
        let mut bytes = [255; 768];
        bytes[mac..mac + 6].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
        bytes
    }));
    let factory = read_factory_with(&mut erased, RTL_DEV_8822CE).unwrap();
    if factory.crystal() != 255
        || factory.rfe() != 255
        || factory.thermal() != [255; 2]
        || factory.power_path(0) != Some(&[255; 42][..])
    {
        return TestResult::Fail("erased factory calibration became a guessed default");
    }
    for did in [RTL_DEV_8821CE, RTL_DEV_8822BE, 0xffff] {
        let mut io = FakeEfuse::new(&records);
        if !matches!(
            read_factory_with(&mut io, did),
            Err(EfuseError::UnsupportedChip)
        ) || !io.writes.is_empty()
        {
            return TestResult::Fail("foreign factory geometry reached EFUSE access");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_retains_same_physical_factory_map_with_linux_packed_geometry
);

fn smoke_rtw88_efuse_sparse_words_and_overrides() -> TestResult {
    // Block 1 word 0 + word 2; then override word 0. Two-byte header
    // encodes block 36 (0x120), the 8822C PCIe factory identity.
    let physical = [
        0x1a, 0x10, 0x11, 0x14, 0x15, 0x1e, 0x20, 0x21, 0x8f, 0x48, 0x02, 0xe0, 0x4c, 0x01, 0x02,
        0x03, 0xff,
    ];
    let mut logical = [0; 768];
    if decode_map(&physical, &mut logical) != Ok(()) {
        return TestResult::Fail("rtw88 rejected valid sparse EFUSE records");
    }
    if logical[8..16] != [0x20, 0x21, 0xff, 0xff, 0x14, 0x15, 0xff, 0xff]
        || logical[0x120..0x126] != [0x02, 0xe0, 0x4c, 1, 2, 3]
        || logical[..8] != [0xff; 8]
    {
        return TestResult::Fail("rtw88 EFUSE word enables/overrides/extended offset wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_efuse_sparse_words_and_overrides
);

fn smoke_rtw88_efuse_rejects_truncated_or_outside_records() -> TestResult {
    let mut logical = [0; 512];
    for physical in [
        &[0x0f][..],             // Missing extended header.
        &[0x0e, 0x11][..],       // Missing second data byte.
        &[0x0c, 1, 2, 3][..],    // Truncated second enabled word.
        &[0xef, 0xfe, 1, 2][..], // Block 127 is outside this map.
    ] {
        if decode_map(physical, &mut logical) != Err(EfuseError::MalformedMap) {
            return TestResult::Fail("rtw88 accepted truncated/outside EFUSE record");
        }
    }
    // A disabled word does not consume bytes; an erased extended header
    // terminates the stream without interpreting the following tail.
    if decode_map(&[0x1f, 0x0f, 0xff, 0x00], &mut logical) != Ok(()) || logical != [0xff; 512] {
        return TestResult::Fail("rtw88 rejected disabled or erased EFUSE header");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_efuse_rejects_truncated_or_outside_records
);

fn smoke_rtw88_efuse_live_sequence_and_pci_mac() -> TestResult {
    let mac = [0x02, 0xe0, 0x4c, 1, 2, 3];
    for (did, header, count, ldo_addr, ldo_value) in [
        (RTL_DEV_8821CE, [0x4f, 0x38], 416, REG_LDO_EFUSE_CTRL + 3, 0),
        (RTL_DEV_8822BE, [0x4f, 0x38], 928, REG_LDO_EFUSE_CTRL + 3, 0),
        (
            RTL_DEV_8822CE,
            [0x8f, 0x48],
            388,
            REG_ANAPARLDO_POW_MAC,
            0xb4,
        ),
    ] {
        let mut records = Vec::from(header);
        records.extend_from_slice(&mac);
        let mut io = FakeEfuse::new(&records);
        // Junk in the protected tail must never be treated as records.
        io.physical[count] = 0;
        if read_mac_with(&mut io, did) != Ok(mac) {
            return TestResult::Fail("rtw88 did not decode the chip-specific PCIe MAC");
        }
        if io.writes[..2] != [(REG_LDO_EFUSE_CTRL, 0x8000_00a5), (ldo_addr, ldo_value)] {
            return TestResult::Fail("rtw88 did not select Wi-Fi bank/disable chip LDO25");
        }
        let byte_reads = &io.writes[2..];
        if byte_reads.len() != count {
            return TestResult::Fail("rtw88 read the wrong physical/protected EFUSE extent");
        }
        for (offset, &(addr, value)) in byte_reads.iter().enumerate() {
            if addr != REG_EFUSE_CTRL || value != 0x2400_0000 | ((offset as u32) << 8) {
                return TestResult::Fail(
                    "rtw88 read trigger/physical address/control preservation wrong",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_efuse_live_sequence_and_pci_mac
);

fn smoke_rtw88_efuse_invalid_identity_and_chip() -> TestResult {
    let mut unknown = FakeEfuse::new(&[]);
    if read_mac_with(&mut unknown, 0xffff) != Err(EfuseError::UnsupportedChip)
        || !unknown.writes.is_empty()
    {
        return TestResult::Fail("rtw88 touched EFUSE for unsupported chip geometry");
    }
    for mac in [[0; 6], [0xff; 6], [1, 0, 0, 0, 0, 1]] {
        let mut records = Vec::from([0x4f, 0x38]);
        records.extend_from_slice(&mac);
        if read_mac_with(&mut FakeEfuse::new(&records), RTL_DEV_8821CE)
            != Err(EfuseError::MacUninitialized)
        {
            return TestResult::Fail("rtw88 accepted a zero/broadcast/multicast factory MAC");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_efuse_invalid_identity_and_chip
);

fn smoke_rtw88_efuse_completion_timeout() -> TestResult {
    let mut io = FakeEfuse::new(&[]);
    io.stalled = true;
    if read_mac_with(&mut io, RTL_DEV_8822CE) != Err(EfuseError::Timeout)
        || io.writes.len() != 3
        || io.analog_ldo != 0xb4
    {
        return TestResult::Fail(
            "rtw88 consumed EFUSE data before completion or continued after timeout",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_efuse_completion_timeout
);
