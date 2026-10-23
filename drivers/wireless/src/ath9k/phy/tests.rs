use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Io {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    delays: Vec<u64>,
}
impl RegisterIo for Io {
    fn read32(&mut self, at: u64) -> u32 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write32(&mut self, at: u64, value: u32) {
        self.regs.insert(at, value);
        self.writes.push((at, value));
    }
    fn delay_us(&mut self, us: u64) {
        self.delays.push(us);
    }
}

fn smoke_ath9k_live_baseband_uses_linux_ini_and_eeprom_gain() -> TestResult {
    // Independent FNV-1a oracles over every (address,value) LE32 pair,
    // extracted from local Linux ar9002_initvals.h columns 4/4/1.
    let hashes = [
        0x44b6ad4bd5ead460u64,
        0x9f6d75b486a50dfd,
        0x1a2f432a8993eaa7,
        0x5e494ed7b20d0612,
    ];
    for (index, expected) in hashes.into_iter().enumerate() {
        let mut io = Io::default();
        io.regs.insert(0x7868, (index / 2) as u32);
        io.regs.insert(0x9874, 0x80000000);
        let mut image = [0; EEPROM_4K_BYTES];
        image[31] = (index % 2) as u8;
        let status = prepare(&mut io, &image).unwrap();
        let first = io
            .writes
            .iter()
            .position(|&(reg, _)| reg == 0x1030)
            .unwrap();
        let mut hash = 0xcbf29ce484222325u64;
        for &(reg, value) in &io.writes[first..first + 655] {
            for byte in (reg as u32)
                .to_le_bytes()
                .into_iter()
                .chain(value.to_le_bytes())
            {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
            }
            if reg + 4 > REQUIRED_BAR {
                return TestResult::Fail("INI escapes checked BAR");
            }
        }
        if status.ini_writes != 655
            || status.xe2_gain != (index >= 2)
            || status.high_power_gain != (index % 2 == 1)
            || hash != expected
            || io.regs.get(&0x7014) != Some(&0x142c)
            || io.regs.get(&0x7048) != Some(&2)
            || io.regs[&0x9874] & 0x3fffffff != (0x30000000 | ((2412 * 0x10000) / 15))
            || io.regs[&0x8048] & 0x02000020 != 0x02000020
            || !io.delays.contains(&100)
            || !io.delays.contains(&1)
        {
            return TestResult::Fail("live INI/PLL/RF sequence differs from Linux source oracle");
        }
        if io.writes.iter().any(|&(reg, value)| {
            (reg == 8 && value & 4 != 0)
                || (reg == 0x840 && value != 0)
                || (reg == 0x981c && value != 0)
                || (reg == 0x24 && value != 0)
        }) {
            return TestResult::Fail("baseband preparation enabled an unowned packet engine");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_live_baseband_uses_linux_ini_and_eeprom_gain
);

fn smoke_ath9k_baseband_rejects_absent_synth_before_writes() -> TestResult {
    let mut io = Io::default();
    io.regs.insert(0x7868, u32::MAX);
    if prepare(&mut io, &[0; EEPROM_4K_BYTES]) != Err(BringUpError::DeviceGone)
        || !io.writes.is_empty()
    {
        return TestResult::Fail("absent RF registers were programmed as an AR9285");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_baseband_rejects_absent_synth_before_writes
);
