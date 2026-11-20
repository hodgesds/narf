use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
#[derive(Default)]
struct Io {
    values: BTreeMap<u64, u32>,
    writes: Vec<[u32; 2]>,
    delays: Vec<u64>,
    gone: Option<u64>,
}
impl RegisterIo for Io {
    fn read32(&mut self, reg: u64) -> u32 {
        if self.gone == Some(reg) {
            return u32::MAX;
        }
        self.values
            .get(&reg)
            .copied()
            .unwrap_or(0x5a5a0000 | reg as u32)
    }
    fn write32(&mut self, reg: u64, value: u32) {
        self.values.insert(reg, value);
        self.writes.push([reg as u32, value]);
    }
    fn delay_us(&mut self, us: u64) {
        self.delays.push(us);
    }
}
fn smoke_ath9k_modal_rf_exact_linux_board_values() -> TestResult {
    for (index, (image, golden)) in [
        (EEPROM_0, GOLDEN_0),
        (EEPROM_1, GOLDEN_1),
        (EEPROM_2, GOLDEN_2),
        (EEPROM_3, GOLDEN_3),
    ]
    .into_iter()
    .enumerate()
    {
        let image: &[u8; EEPROM_4K_BYTES] = image.try_into().unwrap();
        let mut io = Io::default();
        if prepare(&mut io, image, index == 3, index == 3).is_err()
            || io.writes != golden
            || io.delays != [100; 15]
        {
            return TestResult::Fail("AR9285 modal/RF write sequence differs from independent local Linux C function oracle");
        }
    }
    let mut io = Io {
        gone: Some(0x9960),
        ..Io::default()
    };
    let image = EEPROM_3.try_into().unwrap();
    if prepare(&mut io, image, false, false) != Err(BringUpError::DeviceGone)
        || io.writes.len() != 1
    {
        return TestResult::Fail("lost modal register accepted or continued into RF writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k",
    smoke_ath9k_modal_rf_exact_linux_board_values
);
