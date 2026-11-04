use super::*;
use crate::ath9k::{
    channel_width::Geometry,
    phy::ar9280::power::tests::{identity, image},
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Self-completing AR5008 model: the AGC/NF engines (`AR_PHY_AGC_CONTROL`
/// bits 0..1) read back complete, `DO_CAL` clears on the next read, and the
/// three control chains report -90 / -120 / -70 dBm in `AR_PHY_MINCCA_PWR`
/// (bits 19..27). Marker values only, never board data.
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
            (0x4020, 0x0004_00ff),
            (0x4014, 0x1234),
            (0x9914, 1000),
            (0x9c10, 20000),
            (0x9c14, 16000),
            (0x9c18, 0xffff_f000),
            (0xac10, 21000),
            (0xac14, 20000),
            (0xac18, 500),
            (0xbc10, 22000),
            (0xbc14, 18000),
            (0xbc18, 0x1000),
        ] {
            m.values.insert(register, value);
        }
        for (register, dbm) in [(0x9864, -90i32), (0xa864, -120), (0xb864, -70)] {
            m.values.insert(register, ((dbm as u32) & 0x1ff) << 19);
        }
        m
    }
    fn raw(&self, register: u64) -> u32 {
        self.values.get(&register).copied().unwrap_or(0)
    }
    fn count(&self, register: u64) -> usize {
        self.writes.iter().filter(|w| w.0 == register).count()
    }
}
impl RegisterIo for Model {
    fn authorized(&self) -> bool {
        true
    }
    fn read32(&mut self, register: u64) -> u32 {
        let value = self.raw(register);
        if register == 0x9860 {
            self.values.insert(register, value & !3);
            return value & !3;
        }
        if register == 0x9920 {
            self.values.insert(register, value & !0x10000);
            // Like the 0x9860 arm above, the clearing read itself observes
            // clear: hardware finishes DO_CAL within microseconds, far inside
            // the 1 s periodic tick, so the first post-setup tick must see
            // it clear or samples advance every other tick and the 30 s
            // CAL_MAX timeout resets before 64 samples accumulate.
            return value & !0x10000;
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
        Poll::Pending => panic!("self-completing AR5008 model unexpectedly waited"),
    }
}

fn permission(frequency: u16) -> Permission {
    Permission {
        frequency,
        country: *b"US",
        ceiling: 30,
    }
}

fn two(frequency: u16) -> Tune {
    Tune::Two(Geometry::from_frequency(frequency).unwrap())
}

const FIVE: Tune = Tune::Five {
    frequency: 5180,
    frac_n: false,
};

fn run(
    cal: &mut Calibration,
    io: &mut Model,
    chip: Chip,
    tune: Tune,
    rx: u8,
    aspm: bool,
) -> Result<Report, BringUpError> {
    let mut id = identity(0x10);
    id.rx_chainmask = 7;
    // SAFETY: the model is an exclusive, parked fake AR5008 with no DMA.
    ready(unsafe {
        cal.run(
            io,
            chip,
            &id,
            &image(3),
            tune,
            rx,
            aspm,
            permission(tune.center()),
        )
    })
}

fn smoke_ath9k_ar5416_calibration_plain_agc_three_chain_nf_no_iq() -> TestResult {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    let Ok(report) = run(&mut cal, &mut io, Chip::Ar5416, FIVE, 7, false) else {
        return TestResult::Fail("three-chain 5 GHz AR5416 calibration refused");
    };
    // ar5008_hw_set_nf_limits 5 GHz: max -90, min -110, nominal -100.
    if report.measured_noise_dbm != [Some(-90), Some(-120), Some(-70)]
        || report.noise_dbm != [Some(-90), Some(-100), Some(-90)]
    {
        return TestResult::Fail("AR5416 three-chain NF or 5416 limits differ");
    }
    if report.iq != [None; 3] || io.count(0x99f0) != 0 || io.count(0xa920) != 0 {
        return TestResult::Fail("AR5416 ran a per-calibration (supp_cals is 0)");
    }
    // Plain AGC: no FLTR_CAL, no OFF_PWDADC bracket.
    if io.count(0x982c) != 0
        || io
            .writes
            .iter()
            .any(|w| w.0 == 0x9860 && w.1 & 0x10000 != 0)
        || !io.writes.contains(&(0x9860, 1))
    {
        return TestResult::Fail("AR5416 AGC calibration is not the pre-AR9280 form");
    }
    // Nominal -100 loaded on all three chains before the -50 restore.
    let nominal = ((-100i32 << 1) as u32) & 0x1ff;
    for register in [0x9864, 0xa864, 0xb864] {
        if !io
            .writes
            .iter()
            .any(|w| w.0 == register && w.1 & 0x1ff == nominal)
        {
            return TestResult::Fail("AR5416 NF nominal not loaded on every chain");
        }
    }
    if io.writes.iter().any(|w| matches!(w.0, 0x4040 | 0x4004)) {
        return TestResult::Fail("AR5416 without ASPM touched PCIe power save");
    }
    let mut periodic = Periodic::new(&report, 0);
    if periodic.iq_state().is_some() || periodic.private_nf() != [-100; 3] {
        return TestResult::Fail("AR5416 periodic state carries an IQ list entry");
    }
    // First short calibration completes the pending NF; with no list the
    // generation is caldone and reset_calvalid keeps it so.
    match periodic.tick(&mut io, 1000) {
        Ok(tick) if tick.shortcal && tick.noise_floor == Some(-90) && tick.iq.is_none() => {}
        _ => return TestResult::Fail("AR5416 periodic NF tick differs"),
    }
    if !periodic.caldone() || periodic.tick(&mut io, 1_202_000).is_err() || !periodic.caldone() {
        return TestResult::Fail("AR5416 reset_calvalid restarted a calibration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar5416_calibration_plain_agc_three_chain_nf_no_iq
);

fn smoke_ath9k_ar9160_calibration_multi_sample_iq_numchains() -> TestResult {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    // RX 0x5: NF on chains 0 and 2, IQ over numChains = 2 (chains 0, 1).
    let Ok(report) = run(&mut cal, &mut io, Chip::Ar9160, two(2412), 5, false) else {
        return TestResult::Fail("AR9160 0x5 calibration refused");
    };
    // 2 GHz limits: max -80, min -100, nominal -90.
    if report.measured_noise_dbm != [Some(-90), None, Some(-70)]
        || report.noise_dbm != [Some(-90), None, Some(-80)]
    {
        return TestResult::Fail("AR9160 NF chains do not follow the RX mask bits");
    }
    if report.iq != [Some((29, 15)), Some((61, 3)), None] {
        return TestResult::Fail("AR9160 IQ totals or numChains differ from Linux");
    }
    // 64 setups at PER_MIN_LOG_COUNT (2) in IQCAL_LOG_COUNT_MAX.
    if io.count(0x99f0) != MAX_CAL_SAMPLES as usize
        || (io.raw(0x9920) >> 12) & 0xf != 2
        || io.raw(0x9920) & 0x800 == 0
        || io.count(0xb920) != 0
    {
        return TestResult::Fail("AR9160 IQ is not iq_cal_multi_sample");
    }
    if cal.state() != State::Ready || cal.report() != Some(report) {
        return TestResult::Fail("AR9160 calibration report incomplete");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9160_calibration_multi_sample_iq_numchains
);

fn smoke_ath9k_ar9160_periodic_iq_collects_sixty_four_samples() -> TestResult {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    let Ok(report) = run(&mut cal, &mut io, Chip::Ar9160, two(2412), 7, false) else {
        return TestResult::Fail("AR9160 three-chain calibration refused");
    };
    let mut periodic = Periodic::new(&report, 0);
    if periodic.tick(&mut io, 1000).is_err() || !periodic.caldone() {
        return TestResult::Fail("AR9160 first short calibration not caldone");
    }
    // ATH_RESTART_CALINTERVAL: CalValid cleared (WAITING); the long
    // calibration due on the same tick then runs ath9k_hw_reset_calibration
    // (RUNNING, totals and cal_samples zeroed).
    let mut now = 1000 + 1_200_000;
    match periodic.tick(&mut io, now) {
        Ok(tick) if tick.longcal && !tick.shortcal => {}
        _ => return TestResult::Fail("AR9160 restart tick differs"),
    }
    if periodic.caldone()
        || periodic.iq_state() != Some(CalState::Running)
        || periodic.iq_samples() != Some(0)
    {
        return TestResult::Fail("AR9160 reset_calvalid did not restart IQ");
    }
    for sample in 1..=MAX_CAL_SAMPLES {
        now += 1000;
        let Ok(tick) = periodic.tick(&mut io, now) else {
            return TestResult::Fail("AR9160 periodic IQ sample failed");
        };
        if sample < MAX_CAL_SAMPLES {
            if tick.iq.is_some() || periodic.iq_samples() != Some(sample) {
                return TestResult::Fail("AR9160 post-processed before 64 samples");
            }
        } else if tick.iq != Some([Some((29, 15)), Some((61, 3)), Some((38, 14))])
            || periodic.iq_state() != Some(CalState::Done)
            || !periodic.caldone()
        {
            return TestResult::Fail("AR9160 64-sample post-processing differs");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9160_periodic_iq_collects_sixty_four_samples
);

fn smoke_ath9k_ar5008_calibration_refuses_and_aspm_serdes() -> TestResult {
    for (chip, tune, rx, error) in [
        (
            Chip::Ar9280,
            two(2412),
            7,
            BringUpError::UnsupportedRevision,
        ),
        (Chip::Ar5416, two(2412), 8, BringUpError::BadIdentity),
        (Chip::Ar5416, two(2412), 0, BringUpError::BadIdentity),
    ] {
        let mut io = Model::new();
        let mut cal = Calibration::default();
        if run(&mut cal, &mut io, chip, tune, rx, false) != Err(error) || !io.writes.is_empty() {
            return TestResult::Fail("AR5008 calibration wrote before refusing its inputs");
        }
    }
    // AR5418 with ASPM: the pre-AR9280 SerDes words, AR_WA_DEFAULT and
    // AR_PCIE_PM_CTRL_ENA before PHY activation.
    let mut io = Model::new();
    let mut cal = Calibration::default();
    if run(&mut cal, &mut io, Chip::Ar5416, two(2412), 7, true).is_err() {
        return TestResult::Fail("AR5418 ASPM calibration refused");
    }
    let serdes: Vec<u32> = io
        .writes
        .iter()
        .filter(|w| w.0 == 0x4040)
        .map(|w| w.1)
        .collect();
    let at = |w: (u64, u32)| io.writes.iter().position(|x| *x == w);
    if serdes.first() != Some(&0x9248_fc00)
        || serdes.last() != Some(&0x000e_3007)
        || serdes.len() != 9
        || at((0x4004, 0x73f))
            .zip(at((0x981c, 1)))
            .is_none_or(|(w, a)| w > a)
        || io.raw(0x4014) != 0x8_1234
    {
        return TestResult::Fail("AR5418 configpcipowersave(false) differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar5008_calibration_refuses_and_aspm_serdes
);
