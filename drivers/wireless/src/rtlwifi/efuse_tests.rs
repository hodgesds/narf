use super::efuse::{read_mac_with, EfuseError, Io};
use super::regs::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    regs: [u8; 256],
    raw: [u8; 512],
    writes: Vec<(u64, u8)>,
    reads: usize,
    busy: bool,
    stalled: bool,
    settled: usize,
}
impl Model {
    fn new(offset: usize) -> Self {
        let mac = [2, 0xe0, 0x4c, 1, 2, 3];
        let mut logical = [0xff; 512];
        logical[offset..offset + 6].copy_from_slice(&mac);
        let mut raw = [0xff; 512];
        let mut cursor = 0;
        for word_offset in (offset & !1..(offset + 7) & !1).step_by(2) {
            let block = word_offset / 8;
            let mask = 0xf ^ (1 << ((word_offset % 8) / 2));
            if block < 16 {
                raw[cursor] = (block as u8) << 4 | mask;
                cursor += 1;
            } else {
                raw[cursor] = ((block as u8 & 7) << 5) | 0xf;
                raw[cursor + 1] = ((block as u8 >> 3) << 4) | mask;
                cursor += 2;
            }
            raw[cursor..cursor + 2].copy_from_slice(&logical[word_offset..word_offset + 2]);
            cursor += 2;
        }
        let mut regs = [0; 256];
        regs[REG_EFUSE_CTRL as usize + 2] = 0xbc;
        Self {
            regs,
            raw,
            writes: Vec::new(),
            reads: 0,
            busy: false,
            stalled: false,
            settled: 0,
        }
    }
}
impl Io for Model {
    fn read8(&mut self, addr: u64) -> u8 {
        self.regs[addr as usize]
    }
    fn write8(&mut self, addr: u64, value: u8) {
        self.writes.push((addr, value));
        self.regs[addr as usize] = value;
        if addr == REG_EFUSE_CTRL + 3 {
            self.busy = true;
        }
    }
    fn read16(&mut self, addr: u64) -> u16 {
        u16::from_le_bytes([self.regs[addr as usize], self.regs[addr as usize + 1]])
    }
    fn write16(&mut self, addr: u64, value: u16) {
        for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
            self.write8(addr + i as u64, byte);
        }
    }
    fn read32(&mut self, addr: u64) -> u32 {
        self.reads += 1;
        if self.busy || self.stalled {
            self.busy = false;
            return 0;
        }
        let offset = self.regs[addr as usize + 1] as usize
            | ((self.regs[addr as usize + 2] as usize & 3) << 8);
        EFUSE_CTRL_VALID | self.raw[offset] as u32
    }
    fn settle(&mut self) {
        self.settled += 1;
    }
}

fn smoke_rtlwifi_factory_mac_geometry_and_read_lifecycle() -> TestResult {
    for (did, function, offset, bytes, gate) in [
        (RTL_DEV_8188EE, 0, 0xd0, 238, true),
        (RTL_DEV_8192EE, 0, 0xd0, 238, true),
        (RTL_DEV_8723BE, 0, 0xd0, 238, true),
        (RTL_DEV_8821AE, 0, 0xd0, 238, true),
        (RTL_DEV_8192CE, 0, 0x16, 497, false),
        (RTL_DEV_8192CE_ALT, 0, 0x16, 497, false),
        (RTL_DEV_8192DE, 0, 0x55, 497, false),
        (RTL_DEV_8192DE, 1, 0x5b, 497, false),
        (RTL_DEV_8723AE, 0, 0x67, 497, true),
    ] {
        let mut model = Model::new(offset);
        if read_mac_with(&mut model, did, function) != Ok([2, 0xe0, 0x4c, 1, 2, 3])
            || model.settled != bytes
        {
            return TestResult::Fail(
                "rtlwifi factory MAC/physical geometry or settle sequence wrong",
            );
        }
        if model.regs[REG_EFUSE_CTRL as usize + 2] & 0xfc != 0xbc
            || model
                .writes
                .iter()
                .any(|&(addr, value)| addr == REG_EFUSE_CTRL + 3 && value & 0x80 != 0)
            || (gate
                && (model.writes.first() != Some(&(REG_EFUSE_ACCESS, 0x69))
                    || model.writes.last() != Some(&(REG_EFUSE_ACCESS, 0))))
        {
            return TestResult::Fail(
                "rtlwifi EFUSE read programmed cells, clobbered control, or missed access cleanup",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_factory_mac_geometry_and_read_lifecycle
);

fn smoke_rtlwifi_factory_timeout_cleanup_and_unknown_chip() -> TestResult {
    for (did, function) in [(0xffff, 0), (RTL_DEV_8192DE, 2), (RTL_DEV_8822BE, 0)] {
        let mut model = Model::new(0xd0);
        if read_mac_with(&mut model, did, function) != Err(EfuseError::UnsupportedChip)
            || !model.writes.is_empty()
            || model.reads != 0
        {
            return TestResult::Fail(
                "rtlwifi touched EFUSE for unknown geometry/function or rtw88-owned chip",
            );
        }
    }
    let mut model = Model::new(0xd0);
    model.stalled = true;
    if read_mac_with(&mut model, RTL_DEV_8188EE, 0) != Err(EfuseError::Timeout)
        || model.writes.last() != Some(&(REG_EFUSE_ACCESS, 0))
        || model.settled != 0
    {
        return TestResult::Fail("rtlwifi timeout consumed incomplete data or leaked access gate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtlwifi_factory_timeout_cleanup_and_unknown_chip
);
