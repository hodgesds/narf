//! Sparse-map and traced-register regressions for the live probe identity path.

use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::efuse::{decode_map, read_mac_with, EfuseError, EfuseIo};
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
