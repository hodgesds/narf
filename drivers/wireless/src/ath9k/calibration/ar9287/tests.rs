use super::*;
use crate::ath9k::phy::ar9287::power::tests::image;
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Self-completing AR9287 model: AGC/NF/IQ engines finish on the next poll;
/// a completed NF measurement reports -90 dBm on chain 0, -120 on chain 1.
#[derive(Default)]
struct Model {
    values: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    now: u64,
}
impl Model {
    fn new() -> Self {
        let mut m = Self::default();
        for (register, value) in [
            (0x8, 0x20),
            (0x8048, 0x0200_0020),
            (0x4020, 0x0018_03ff),
            (0x9914, 1000),
            (0x9c10, 20000),
            (0x9c14, 16000),
            (0x9c18, 0xffff_f000),
            (0xac10, 21000),
            (0xac14, 20000),
            (0xac18, 500),
        ] {
            m.values.insert(register, value);
        }
        m
    }
    fn raw(&self, register: u64) -> u32 {
        self.values.get(&register).copied().unwrap_or(0)
    }
}
impl RegisterIo for Model {
    fn authorized(&self) -> bool {
        true
    }
    fn read32(&mut self, register: u64) -> u32 {
        let value = self.raw(register);
        if register == 0x9860 && value & 3 != 0 {
            if value & 2 != 0 && value & 0x8000 != 0 {
                for (nf, dbm) in [(0x9864, -90i32), (0xa864, -120)] {
                    let old = self.raw(nf) & !0x1ff0_0000;
                    self.values.insert(nf, old | (((dbm as u32) & 0x1ff) << 20));
                }
            }
            self.values.insert(register, value & !3);
        }
        if register == 0x9920 {
            self.values.insert(register, value & !0x10000);
        }
        value
    }
    fn write32(&mut self, register: u64, value: u32) {
        self.writes.push((register, value));
        self.values.insert(register, value);
    }
    fn delay_us(&mut self, us: u64) {
        self.now += us;
    }
}
impl Io for Model {
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn settle(&mut self, us: u64) {
        self.now += us;
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("self-completing AR9287 model unexpectedly waited"),
    }
}

fn run(cal: &mut Calibration, io: &mut Model, map: &[u8], rx: u8) -> Result<Report, BringUpError> {
    // SAFETY: the model is an exclusive, parked fake AR9287 with no DMA.
    ready(unsafe { cal.run(io, map, rx, permission()) })
}

fn permission() -> Permission {
    Permission {
        frequency: 2422,
        country: *b"US",
        ceiling: 40,
    }
}

fn smoke_ath9k_ar9287_calibration_two_chain_agc_nf_iq() -> TestResult {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    let report = match run(&mut cal, &mut io, &image(3), 3) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("two-chain AR9287 calibration refused"),
    };
    // Chain 0: |corr| 4096 / 140 = 29 (negative keeps it), q 80 - 64 -> 15.
    // Chain 1: 64 - 500 / 160 = 61, q 21000 / 312 - 64 = 3.
    if report.iq != [Some((29, 15)), Some((61, 3))] {
        return TestResult::Fail("AR9287 per-chain IQ coefficients differ");
    }
    if report.measured_noise_dbm != [Some(-90), Some(-120)]
        || report.noise_dbm != [Some(-97), Some(-120)]
    {
        return TestResult::Fail("AR9287 NF limits (-127/-112/-97) not applied");
    }
    if report.init_pdadc != 0x55 || cal.state() != State::Ready || cal.report() != Some(report) {
        return TestResult::Fail("AR9287 calibration report incomplete");
    }
    if io.raw(0x9920) != 0xabaf || io.raw(0xa920) != 0x7a3 {
        return TestResult::Fail("AR9287 IQ correction registers differ");
    }
    if io.raw(0x9864) & 0x1ff != 0x19c || io.raw(0xa864) & 0x1ff != 0x19c {
        return TestResult::Fail("AR9287 maxCCA was not restored to -50 on both chains");
    }
    let at = |w: (u64, u32)| io.writes.iter().position(|x| *x == w);
    let (Some(rates), Some(active), Some(fltr), Some(agc), Some(done)) = (
        at((0x993c, 63)),
        at((0x981c, 1)),
        at((0x9860, 0x10000)),
        at((0x9860, 0x10001)),
        io.writes
            .iter()
            .rposition(|w| w.0 == 0x9860 && w.1 & 0x10000 == 0),
    ) else {
        return TestResult::Fail("AR9287 power/activation/AGC writes missing");
    };
    if !(rates < active && active < fltr && fltr < agc && agc < done) {
        return TestResult::Fail("AR9287 init order differs from ar9002_hw_init_cal");
    }
    if io.writes.iter().any(|w| w.0 == 0x7834 || w.0 == 0x7830) {
        return TestResult::Fail("AR9285-only PA/CLC touched on AR9287");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9287_calibration_two_chain_agc_nf_iq
);

fn smoke_ath9k_ar9287_calibration_one_chain_leaves_chain1() -> TestResult {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    let report = match run(&mut cal, &mut io, &image(1), 1) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("one-chain AR9287 calibration refused"),
    };
    if report.iq[1].is_some() || report.noise_dbm[1].is_some() {
        return TestResult::Fail("receive chain 1 reported while disabled");
    }
    if io.writes.iter().any(|w| w.0 == 0xa920 || w.0 == 0xa864) {
        return TestResult::Fail("disabled chain 1 was calibrated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9287_calibration_one_chain_leaves_chain1
);

fn smoke_ath9k_ar9287_calibration_refusals() -> TestResult {
    let mut cal = Calibration::default();
    let mut io = Model::new();
    if run(&mut cal, &mut io, &image(3), 0) != Err(BringUpError::BadIdentity)
        || !io.writes.is_empty()
    {
        return TestResult::Fail("empty RX chainmask accepted");
    }
    let mut io = Model::new();
    io.values.insert(0x981c, 1);
    if run(&mut cal, &mut io, &image(3), 3) != Err(BringUpError::BadState) || !io.writes.is_empty()
    {
        return TestResult::Fail("active PHY accepted for initial calibration");
    }
    let mut closed = image(3);
    closed[31] = 0;
    let mut io = Model::new();
    if run(&mut cal, &mut io, &closed, 3) != Err(BringUpError::BadCalibration)
        || !io.writes.is_empty()
        || cal.state() != State::Failed
    {
        return TestResult::Fail("closed-loop map reached the PHY");
    }
    let mut io = Model::new();
    if run(&mut cal, &mut io, &image(3), 3) != Err(BringUpError::BadState) {
        return TestResult::Fail("failed AR9287 calibration owner was reusable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9287_calibration_refusals
);

fn smoke_ath9k_ar9287_olc_temp_compensation_follows_linux() -> TestResult {
    let mut map = image(3);
    map[4] = 3; // EEPROM minor 3 (>= AR9287_EEP_MINOR_VER_2).
    map[5] = 0xe0;
    for (current, slope, expected, field) in [
        (101u32, 8i8, 8, 0x2000u32),
        (69, 8, -8, 0xe000),
        (90, -3, -6, 0xe800),
    ] {
        map[33] = slope as u8;
        let mut io = Model::new();
        io.values.insert(0xa264, current << 1);
        io.values.insert(0xb398, !0xfc00u32);
        match olc_temp_compensation(&mut io, &map, 85) {
            Ok(Some(delta)) if delta == expected => {}
            _ => return TestResult::Fail("AR9287 OLC temperature delta differs"),
        }
        if io.raw(0xa398) != field || io.raw(0xb398) != (!0xfc00 | field) {
            return TestResult::Fail("OLC_TEMP_COMP not written to both chains");
        }
    }
    let mut old = map.clone();
    old[4] = 1; // Minor 1: tempSensSlope is not read, delta 0.
    let mut io = Model::new();
    io.values.insert(0xa264, 101 << 1);
    if olc_temp_compensation(&mut io, &old, 85) != Ok(Some(0)) {
        return TestResult::Fail("pre-minor-2 slope was used");
    }
    for (current, init) in [(0u32, 85u8), (101, 0)] {
        let mut io = Model::new();
        io.values.insert(0xa264, current << 1);
        if olc_temp_compensation(&mut io, &map, init) != Ok(None) || !io.writes.is_empty() {
            return TestResult::Fail("OLC compensation ran before a transmitted frame");
        }
    }
    if adc_dc_mismatch(0x1234, 0x5678, (-82000i32) as u32, (-17000i32) as u32) != (1, 508) {
        return TestResult::Fail("ADC DC mismatch arithmetic differs from Linux u32 math");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9287_olc_temp_compensation_follows_linux
);

fn smoke_ath9k_ar9287_ht40_adc_dc_offset_correction() -> TestResult {
    let mut io = Model::new();
    for (register, value) in [
        (0x9c10, 0x1234),
        (0x9c14, 0x5678),
        (0x9c18, (-82000i32) as u32),
        (0x9c1c, (-17000i32) as u32),
        (0x99b4, 0x4000_1000),
    ] {
        io.values.insert(register, value);
    }
    match ready(adc_dc(&mut io, 1)) {
        Ok([Some((1, 508)), None]) => {}
        _ => return TestResult::Fail("AR9287 ADC DC mismatch differs"),
    }
    // val &= 0xc0000fff; val |= q << 12 | i << 21; then OFFSET_CORR_ENABLE.
    if io.raw(0x99f0) != 2 || io.raw(0x99b4) != 0xc03f_c000 || io.raw(0xa9b4) != 0 {
        return TestResult::Fail("AR9287 ADC DC correction register differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9287_ht40_adc_dc_offset_correction
);
