use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Io {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    authorized: bool,
    reads: usize,
}
impl Io {
    fn new() -> Self {
        Self {
            regs: BTreeMap::new(),
            writes: Vec::new(),
            authorized: true,
            reads: 0,
        }
    }
}
impl RegisterIo for Io {
    fn authorized(&self) -> bool {
        self.authorized
    }
    fn read32(&mut self, at: u64) -> u32 {
        self.reads += 1;
        *self.regs.get(&at).unwrap_or(&(0x5a5a0000 | at as u32))
    }
    fn write32(&mut self, at: u64, value: u32) {
        self.regs.insert(at, value);
        self.writes.push((at, value));
    }
}
fn smoke_ath9k_native_pdadc_matches_linux_all_registers() -> TestResult {
    for (frequency, eeprom, golden) in [
        (2412, EEPROM_0, GOLDEN_0),
        (2422, EEPROM_1, GOLDEN_1),
        (2437, EEPROM_2, GOLDEN_2),
        (2462, EEPROM_3, GOLDEN_3),
        (2407, EEPROM_4, GOLDEN_4),
        (2467, EEPROM_5, GOLDEN_5),
        (2412, EEPROM_6, GOLDEN_6),
    ] {
        let image = eeprom.try_into().unwrap();
        let mut io = Io::new();
        if program(&mut io, image, frequency).is_err()
            || io.writes.len() != golden.len()
            || io
                .writes
                .iter()
                .zip(golden)
                .any(|(&(r, v), g)| [r as u32, v] != *g)
        {
            return TestResult::Fail("EEPROM PDADC/gain interpolation differs from independent Linux full-register oracle");
        }
        if io
            .writes
            .iter()
            .any(|&(r, _)| r != 0xa258 && r != 0xa26c && !(0xa280..=0xa2fc).contains(&r))
        {
            return TestResult::Fail(
                "detector calibration modified PHY/queue/DMA activation state",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_native_pdadc_matches_linux_all_registers
);
fn smoke_ath9k_invalid_detector_calibration_never_programs_table() -> TestResult {
    let base: [u8; EEPROM_4K_BYTES] = EEPROM_1.try_into().unwrap();
    for case in 0..8 {
        let mut image = base;
        match case {
            0 => image[72] = 0,
            1 => image[120..123].fill(255),
            2 => image[121] = 111,
            3 => image[124] = 7,
            4 => image[133..138].reverse(),
            5 => image[123..128].fill(8),
            6 => image[76] = 16,
            7 => image[127] = 255,
            _ => unreachable!(),
        }
        let mut io = Io::new();
        if program(&mut io, &image, 2412) != Err(BringUpError::BadCalibration)
            || !io.writes.is_empty()
        {
            return TestResult::Fail(
                "malformed/empty calibration published partial detector settings",
            );
        }
    }
    let mut io = Io::new();
    io.regs.insert(0xa258, u32::MAX);
    if program(&mut io, &base, 2412) != Err(BringUpError::DeviceGone) || !io.writes.is_empty() {
        return TestResult::Fail("absent detector control register was programmed");
    }
    let mut io = Io::new();
    io.authorized = false;
    if program(&mut io, &base, 2412) != Err(BringUpError::DeviceGone)
        || !io.writes.is_empty()
        || io.reads != 0
    {
        return TestResult::Fail("revoked detector calibration entered native register operation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_invalid_detector_calibration_never_programs_table
);

fn smoke_ath9k_detector_rejects_actual_revoked_native_authority() -> TestResult {
    use narf_bus::{BarKind, BusDeviceCap, MmioRegion};
    use narf_capabilities::{Cap, Write};
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0, // Any native register access would fault.
        len: super::super::REQUIRED_BAR,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let mut io = crate::ath9k::identity::Registers::new(region, cap);
    cap.revoke();
    if program(&mut io, EEPROM_0.try_into().unwrap(), 2412) != Err(BringUpError::DeviceGone) {
        return TestResult::Fail("revoked native detector publication remained authorized");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_detector_rejects_actual_revoked_native_authority
);
