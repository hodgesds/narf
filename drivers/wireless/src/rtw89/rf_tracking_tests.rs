//! Stored source DPK/PWSF vectors through an inert register owner; no RF grant.
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    words: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32, u32)>,
    fail_write: Option<usize>,
    live: bool,
}
impl Model {
    fn new() -> Self {
        let mut words = BTreeMap::new();
        words.insert(DPK_TRK, 0);
        for (path, thermal, txagc, tp, hardware_offset, txdpd) in [
            (0, 30, 0xfe0a0001, 3, false, false),
            (1, 36, 0x04140002, 7, true, true),
        ] {
            let offset = path << 13;
            words.insert(THERMAL + offset, thermal << 24);
            words.insert(TXAGC + offset, txagc);
            words.insert(TXAGC_TP + offset, tp);
            words.insert(TSSI_AVG + offset, 1 << 31);
            words.insert(TSSI_TRK + offset, 0x18000000);
            words.insert(TXDPD + offset, u32::from(txdpd) << 28);
            words.insert(DPD_COM + (path << 8), u32::from(hardware_offset) << 15);
            words.insert(DPD_BND + (path << 8), 0xa600c600);
        }
        Self {
            words,
            writes: Vec::new(),
            fail_write: None,
            live: true,
        }
    }
}
impl Hw for Model {
    fn current(&mut self) -> Result<(), power::Error> {
        if self.live {
            Ok(())
        } else {
            Err(power::Error::Access)
        }
    }
    fn read_bb(&mut self, address: u32) -> Result<u32, power::Error> {
        self.current()?;
        if !readable(address) {
            return Err(power::Error::Unsupported);
        }
        self.words
            .get(&address)
            .copied()
            .ok_or(power::Error::Access)
    }
    fn write_bb(&mut self, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
        self.current()?;
        if !writable(address) || mask != 0x01ff01ff || value & !mask != 0 {
            return Err(power::Error::Unsupported);
        }
        if self.fail_write == Some(self.writes.len() + 1) {
            return Err(power::Error::Access);
        }
        let old = *self.words.get(&address).ok_or(power::Error::Access)?;
        self.words.insert(address, old & !mask | value);
        self.writes.push((address, mask, value));
        Ok(())
    }
}
pub(in crate::rtw89) fn tracker() -> Tracker {
    let paths = [
        dpk::Path {
            thermal: 32,
            pwsf: 120,
            gain: 0x5b,
            ..Default::default()
        },
        dpk::Path {
            thermal: 40,
            pwsf: 120,
            gain: 0x5b,
            ..Default::default()
        },
    ];
    Tracker::new(Inputs::from_completed(paths).unwrap())
}
fn smoke_rtw8852b_periodic_dpk_actual_thermal_tssi_and_pwsf_source_vectors() -> TestResult {
    let mut model = Model::new();
    let mut track = tracker();
    let window = Window {
        low: 100,
        high: 140,
    };
    // A:120+(32-30)*3/2-2+3-10=114. B:hardware-offset forces0,
    // TXDPD skips TP-BB, so120+(40-36)*3/2=126.
    if track.step(&mut model, window).is_err()
        || model.writes
            != [
                (0x81b4, 0x01ff01ff, 0x00720072),
                (0x82b4, 0x01ff01ff, 0x007e007e),
            ]
        || model.words[&0x81b4] != 0xa672c672
        || model.words[&0x82b4] != 0xa67ec67e
    {
        return TestResult::Fail("source two-path thermal/TSSI PWSF or preserved register holes");
    }
    model.words.insert(THERMAL, 34 << 24);
    model.words.insert(THERMAL + 0x2000, 0);
    model.writes.clear();
    // Source thermal EWMA(4,4): A becomes31; zero B retains36.
    if track.step(&mut model, window).is_err()
        || model.writes
            != [
                (0x81b4, 0x01ff01ff, 0x00700070),
                (0x82b4, 0x01ff01ff, 0x007e007e),
            ]
    {
        return TestResult::Fail("actual thermal EWMA or zero sample retention");
    }
    model.words.insert(DPK_TRK, 1 << 31);
    model.writes.clear();
    if track.step(&mut model, window).is_err() || !model.writes.is_empty() {
        return TestResult::Fail("hardware-disabled DPK tracking changed power fields");
    }
    let mut model = Model::new();
    model.words.insert(TXAGC, 0x807f0001);
    model.words.insert(TXAGC_TP, 0);
    model.words.insert(THERMAL, 32 << 24);
    if tracker()
        .step(&mut model, Window { low: 0, high: 511 })
        .is_err()
        || model.writes.first() != Some(&(0x81b4, 0x01ff01ff, 0x01790179))
    {
        return TestResult::Fail("signed TXAGC and actual9-bit PWSF wrapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/tracking",
    smoke_rtw8852b_periodic_dpk_actual_thermal_tssi_and_pwsf_source_vectors
);

fn smoke_rtw8852b_periodic_dpk_window_tssi_source_loss_and_partial_fault_retire() -> TestResult {
    let mut model = Model::new();
    let mut track = tracker();
    if track
        .step(
            &mut model,
            Window {
                low: 115,
                high: 140,
            },
        )
        .is_ok()
        || !model.writes.is_empty()
        || track.step(&mut model, Window { low: 0, high: 511 }).is_ok()
    {
        return TestResult::Fail("out-of-envelope PWSF changed RF or retired tracker revived");
    }
    for (address, value) in [(TSSI_AVG, 0), (TSSI_TRK, 0), (THERMAL, u32::MAX)] {
        let mut model = Model::new();
        model.words.insert(address, value);
        if tracker()
            .step(&mut model, Window { low: 0, high: 511 })
            .is_ok()
            || !model.writes.is_empty()
        {
            return TestResult::Fail(
                "missing actual TSSI/read source admitted periodic power write",
            );
        }
    }
    let mut model = Model::new();
    model.fail_write = Some(2);
    let mut track = tracker();
    if track.step(&mut model, Window { low: 0, high: 511 }).is_ok() || model.writes.len() != 1 {
        return TestResult::Fail("second-path actual write fault was not retained as partial");
    }
    model.fail_write = None;
    if track.step(&mut model, Window { low: 0, high: 511 }).is_ok() || model.writes.len() != 1 {
        return TestResult::Fail("partial native power owner silently retried/reopened");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/tracking",
    smoke_rtw8852b_periodic_dpk_window_tssi_source_loss_and_partial_fault_retire
);
