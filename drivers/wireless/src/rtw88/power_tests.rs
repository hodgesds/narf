use super::power::{power_on_with, Io, PowerError};
use super::regs::*;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    regs: Vec<u8>,
    writes: Vec<(u64, usize, u32)>,
    polls: Vec<(u64, u8, u8)>,
    failures: u8,
}
impl Model {
    fn new(cut: u8, warm: bool) -> Self {
        let mut regs = vec![0x55; 0x1200];
        regs[0xf0..0xf4].copy_from_slice(&((cut as u32) << 12).to_le_bytes());
        regs[REG_CR as usize] = if warm { 0 } else { 0xea };
        regs[REG_MCUFW_CTRL as usize..REG_MCUFW_CTRL as usize + 4]
            .copy_from_slice(&(1u32 << 20).to_le_bytes());
        Self {
            regs,
            writes: Vec::new(),
            polls: Vec::new(),
            failures: 0,
        }
    }
}
impl Io for Model {
    fn read8(&mut self, a: u64) -> u8 {
        self.regs[a as usize]
    }
    fn write8(&mut self, a: u64, v: u8) {
        self.regs[a as usize] = v;
        self.writes.push((a, 1, v as u32));
    }
    fn read16(&mut self, a: u64) -> u16 {
        u16::from_le_bytes(self.regs[a as usize..a as usize + 2].try_into().unwrap())
    }
    fn read32(&mut self, a: u64) -> u32 {
        u32::from_le_bytes(self.regs[a as usize..a as usize + 4].try_into().unwrap())
    }
    fn write32(&mut self, a: u64, v: u32) {
        self.regs[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        self.writes.push((a, 4, v));
    }
    fn delay_us(&mut self, _: u64) {}
    fn poll8(&mut self, a: u64, mask: u8, target: u8) -> bool {
        self.polls.push((a, mask, target));
        if self.failures != 0 {
            self.failures -= 1;
            return false;
        }
        self.regs[a as usize] = (self.regs[a as usize] & !mask) | (target & mask);
        true
    }
}

fn smoke_rtw88_linux_chip_power_sequences() -> TestResult {
    for did in [RTL_DEV_8821CE, RTL_DEV_8822BE, RTL_DEV_8822CE] {
        for warm in [false, true] {
            let mut model = Model::new(0, warm);
            if power_on_with(&mut model, did) != Ok(()) {
                return TestResult::Fail("rtw88 Linux PCI power sequence failed");
            }
            if model.writes.iter().any(|&(a, _, _)| a == 0x93) != warm
                || model.polls.last() != Some(&(5, 1, 0))
                || model.regs[0x1103] != 0x5c
                || model.read32(REG_MCUFW_CTRL) & (1 << 20) != 0
                || model.read32(0x40) & (1 << 19) != 0
            {
                return TestResult::Fail(
                    "rtw88 warm-card cycle, PMU handshake, system setup, or flash disable wrong",
                );
            }
            let sys = if did == RTL_DEV_8822BE { 0xdc } else { 0xd8 };
            if model.regs[REG_SYS_FUNC_EN as usize + 1] != 0x55 | sys
                || model.read32(0x1080) & ((1 << 16) | (1 << 8)) != ((1 << 16) | (1 << 8))
            {
                return TestResult::Fail("rtw88 chip-specific SYS enables/DMEM reset wrong");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_linux_chip_power_sequences
);

fn smoke_rtw88_linux_power_cut_and_retry() -> TestResult {
    for cut in [0, 2] {
        let mut model = Model::new(cut, false);
        model.failures = 1;
        if power_on_with(&mut model, RTL_DEV_8822BE) != Ok(()) {
            return TestResult::Fail("rtw88 did not recover the first PCI power polling failure");
        }
        let c_only = model.writes.iter().any(|&(a, _, _)| a == 0x10a8);
        if c_only != (cut == 2) || model.polls[..2] != [(6, 2, 2), (6, 2, 2)] {
            return TestResult::Fail(
                "rtw88 selected wrong cut-specific rows or failed polling retry",
            );
        }
        if !model
            .writes
            .windows(2)
            .any(|ops| ops == [(4, 1, 0x5d), (4, 1, 0x55)])
        {
            return TestResult::Fail("rtw88 PCI retry clobbered unrelated PFM_WOWL bits");
        }
    }
    let mut model = Model::new(0, false);
    model.failures = 2;
    if power_on_with(&mut model, RTL_DEV_8822CE) != Err(PowerError::Timeout)
        || model.writes.iter().any(|&(a, _, _)| a == 0x1080)
    {
        return TestResult::Fail("rtw88 ignored terminal power timeout or continued system setup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_linux_power_cut_and_retry
);

fn smoke_rtw88_linux_power_rejects_unknown_geometry() -> TestResult {
    for (did, cut, error) in [
        (0xffff, 0, PowerError::UnsupportedChip),
        (RTL_DEV_8822CE, 7, PowerError::UnknownCut),
    ] {
        let mut model = Model::new(cut, false);
        if power_on_with(&mut model, did) != Err(error) || !model.writes.is_empty() {
            return TestResult::Fail("rtw88 issued power writes for unsupported chip/cut");
        }
    }
    let mut model = Model::new(0, false);
    model.regs[0xf0..0xf4].fill(0xff);
    if power_on_with(&mut model, RTL_DEV_8822CE) != Err(PowerError::DeviceGone)
        || !model.writes.is_empty()
    {
        return TestResult::Fail("rtw88 wrote PMU registers after an absent-device read");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_linux_power_rejects_unknown_geometry
);
