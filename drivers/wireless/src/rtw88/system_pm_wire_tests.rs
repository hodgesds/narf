//! Independent DBI engine; source readiness and copy are literal byte receipts.
use super::*;
use alloc::{vec, vec::Vec};
use narf_capabilities::{Cap, NoopOp, Write};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Device {
    registers: Vec<u8>,
    word: u16,
    link: u8,
    writes: Vec<(u64, u16)>,
    lose: bool,
    gone: bool,
    revoke: bool,
    cap: Cap<narf_bus::BusDeviceCap, Write>,
}
impl Device {
    fn new() -> Self {
        Self {
            registers: vec![0; 0x400],
            word: 0,
            link: 0xa5,
            writes: Vec::new(),
            lose: false,
            gone: false,
            revoke: false,
            cap: Cap::bootstrap(),
        }
    }
}
impl Io for Device {
    fn permission(&mut self) -> bool {
        self.cap.invoke(NoopOp).is_ok()
    }
    fn read8(&mut self, a: u64) -> u8 {
        if a == 0x3f2 && self.gone {
            return 255;
        }
        self.registers[a as usize]
    }
    fn write8(&mut self, a: u64, v: u8) {
        self.writes.push((a, u16::from(v)));
        self.registers[a as usize] = v;
        if a == 0x3f2 {
            match (self.word, v) {
                (0x718, 2) => {
                    self.registers[0x3ed] = self.link;
                    if self.revoke {
                        self.cap.revoke();
                    }
                }
                (0x2718, 1) if !self.lose => self.link = self.registers[0x3e9],
                _ => {}
            }
            self.registers[0x3f2] = 0;
        }
    }
    fn read16(&mut self, a: u64) -> u16 {
        u16::from_le_bytes(
            self.registers[a as usize..a as usize + 2]
                .try_into()
                .unwrap(),
        )
    }
    fn read32(&mut self, a: u64) -> u32 {
        u32::from_le_bytes(
            self.registers[a as usize..a as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn write32(&mut self, a: u64, v: u32) {
        self.registers[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
    }
}
impl Registers for Device {
    fn write16(&mut self, a: u64, v: u16) {
        self.writes.push((a, v));
        self.word = v;
    }
}
fn smoke_rtw8822ce_system_pm_rfe6_literal_dbi_pad_and_readback() -> TestResult {
    let mut device = Device::new();
    if clkreq_pad(&mut device, true) != Ok(())
        || device.link != 0xa4
        || device.writes
            != vec![
                (0x3f0, 0x718),
                (0x3f2, 2),
                (0x3e9, 0xa4),
                (0x3f0, 0x2718),
                (0x3f2, 1),
                (0x3f0, 0x718),
                (0x3f2, 2),
            ]
        || clkreq_pad(&mut device, false) != Ok(())
        || device.link != 0xa5
    {
        return TestResult::Fail("source DBI byte/WREN/pad transaction/readback mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/system_pm",
    smoke_rtw8822ce_system_pm_rfe6_literal_dbi_pad_and_readback
);
fn smoke_rtw8822ce_system_pm_dbi_source_loss_and_lost_write_deny_success() -> TestResult {
    for fault in 0..3 {
        let mut device = Device::new();
        match fault {
            0 => device.lose = true,
            1 => device.gone = true,
            _ => device.revoke = true,
        }
        if clkreq_pad(&mut device, true).is_ok()
            || device.link != 0xa5
            || fault == 2 && device.writes.iter().any(|&(a, _)| a == 0x3e9)
        {
            return TestResult::Fail(
                "DBI absence/lost write/original cap loss fabricated pad receipt",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/system_pm",
    smoke_rtw8822ce_system_pm_dbi_source_loss_and_lost_write_deny_success
);
