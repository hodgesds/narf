use super::*;
use crate::ath9k::{
    channel_width::Geometry,
    identity::RegisterIo,
    phy::ar9280::power::tests::{identity, image},
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Self-completing AR9280 model: AGC/NF/IQ engines finish on the next poll;
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
            (0x4020, 0x0008_03ff),
            (0x4014, 0x1234),
            (0x982c, 0x8000),
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
        Poll::Pending => panic!("self-completing AR9280 model unexpectedly waited"),
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
    tune: Tune,
    rx: u8,
    aspm: bool,
    frequency: u16,
) -> Result<Report, BringUpError> {
    // SAFETY: the model is an exclusive, parked fake AR9280 with no DMA.
    ready(unsafe {
        cal.run(
            io,
            &identity(0x10),
            &image(3),
            tune,
            rx,
            aspm,
            permission(frequency),
        )
    })
}

fn smoke_ath9k_ar9280_calibration_pwdadc_agc_two_chain_2ghz() -> TestResult {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    let report = match run(&mut cal, &mut io, two(2412), 3, false, 2412) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("two-chain 2.4 GHz AR9280 calibration refused"),
    };
    if report.iq != [Some((29, 15)), Some((61, 3))] || report.five_ghz {
        return TestResult::Fail("AR9280 per-chain IQ coefficients differ");
    }
    if report.measured_noise_dbm != [Some(-90), Some(-120)]
        || report.noise_dbm != [Some(-97), Some(-120)]
    {
        return TestResult::Fail("AR9280 2 GHz NF limits (-127/-112/-97) not applied");
    }
    if cal.state() != State::Ready || cal.report() != Some(report) {
        return TestResult::Fail("AR9280 calibration report incomplete");
    }
    // ar9002_hw_init_cal below AR9287 1.1: OFF_PWDADC cleared, FLTR_CAL
    // set, AGC CAL, OFF_PWDADC set, FLTR_CAL cleared.
    let at = |w: (u64, u32)| io.writes.iter().position(|x| *x == w);
    let (Some(active), Some(clear), Some(fltr), Some(set)) = (
        at((0x981c, 1)),
        at((0x982c, 0)),
        at((0x9860, 0x10000)),
        at((0x982c, 0x8000)),
    ) else {
        return TestResult::Fail("AR9280 OFF_PWDADC bracket missing");
    };
    let Some(done) = io
        .writes
        .iter()
        .rposition(|w| w.0 == 0x9860 && w.1 & 0x10000 == 0)
    else {
        return TestResult::Fail("AR9280 FLTR_CAL never cleared");
    };
    if !(active < clear && clear < fltr && fltr < set && set < done) {
        return TestResult::Fail("AR9280 init order differs from ar9002_hw_init_cal");
    }
    // PCI part / ASPM off: no SerDes or workaround write.
    if io
        .writes
        .iter()
        .any(|w| matches!(w.0, 0x4040 | 0x4044 | 0x4004 | 0x4014))
    {
        return TestResult::Fail("AR9280 without ASPM touched PCIe power save");
    }
    // Rates programmed before PHY activation.
    if at((0x993c, 63)).is_none_or(|rates| rates > active) {
        return TestResult::Fail("AR9280 transmit power not programmed before activation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9280_calibration_pwdadc_agc_two_chain_2ghz
);

fn smoke_ath9k_ar9280_calibration_5ghz_limits_and_pcie_workaround() -> TestResult {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    let report = match run(&mut cal, &mut io, FIVE, 3, true, 5180) {
        Ok(report) => report,
        Err(_) => return TestResult::Fail("two-chain 5 GHz AR9280 calibration refused"),
    };
    // AR9280 5 GHz limits: -90 clamps to max -102; -120 is within -122.
    if !report.five_ghz || report.noise_dbm != [Some(-102), Some(-120)] {
        return TestResult::Fail("AR9280 5 GHz NF limits (-122/-112/-102) not applied");
    }
    // Initial load used the 5 GHz nominal (-112) before the -50 restore.
    if !io
        .writes
        .iter()
        .any(|w| w.0 == 0x9864 && w.1 & 0x1ff == ((-112i32 << 1) as u32) & 0x1ff)
    {
        return TestResult::Fail("AR9280 5 GHz NF history nominal not loaded");
    }
    let at = |w: (u64, u32)| io.writes.iter().position(|x| *x == w);
    let (Some(serdes), Some(wa), Some(active)) = (
        at((0x4040, 0x9248_fd00)),
        at((0x4004, 0x0040_073b)),
        at((0x981c, 1)),
    ) else {
        return TestResult::Fail("AR9280 iniPcieSerdes / AR9280_WA_DEFAULT missing");
    };
    if !(serdes < wa && wa < active) || io.raw(0x4014) != 0x8_1234 {
        return TestResult::Fail("AR9280 PCIe power save order or L1 enable differs");
    }
    let periodic = periodic(&report, 0);
    if periodic.private_nf() != [-112, -112] || periodic.caldone() {
        return TestResult::Fail("AR9280 periodic history not at the band nominal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9280_calibration_5ghz_limits_and_pcie_workaround
);

fn smoke_ath9k_ar9280_calibration_refuses_before_writes() -> TestResult {
    for (tune, rx, frequency, error) in [
        (two(2412), 3, 2417, BringUpError::Policy),
        (FIVE, 3, 5200, BringUpError::Policy),
        (two(2412), 4, 2412, BringUpError::BadIdentity),
        (two(2412), 0, 2412, BringUpError::BadIdentity),
    ] {
        let mut io = Model::new();
        let mut cal = Calibration::default();
        if run(&mut cal, &mut io, tune, rx, true, frequency) != Err(error)
            || !io.writes.is_empty()
            || cal.state() != State::New
        {
            return TestResult::Fail("AR9280 calibration wrote before refusing its inputs");
        }
    }
    // A running PHY is refused before any write.
    let mut io = Model::new();
    io.values.insert(0x981c, 1);
    let mut cal = Calibration::default();
    if run(&mut cal, &mut io, two(2412), 3, false, 2412) != Err(BringUpError::BadState)
        || !io.writes.is_empty()
    {
        return TestResult::Fail("AR9280 calibration accepted an active PHY");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9280_calibration_refuses_before_writes
);

fn smoke_ath9k_ar9280_dual_band_permission_refuses_dfs_and_no_ir() -> TestResult {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let rule = |start, end, power, flags| RegRule {
        freq_start_mhz: start,
        freq_end_mhz: end,
        max_bandwidth_mhz: 80,
        max_power_dbm: power,
        flags,
    };
    let mut domain = RegulatoryDomain {
        country_code: *b"US",
        rules: alloc::vec![
            rule(2402, 2472, 30, RegFlags::empty()),
            rule(5170, 5250, 23, RegFlags::empty()),
            rule(5250, 5330, 23, RegFlags::DFS),
        ],
    };
    let at = |d: &RegulatoryDomain, f| Permission::from_domain_dual(d, f);
    // Both bands under the shared 20 dBm (40 half-dBm) cap.
    if at(&domain, 2412).map(|p| (p.frequency, p.ceiling)) != Ok((2412, 40))
        || at(&domain, 5180).map(|p| (p.frequency, p.ceiling)) != Ok((5180, 40))
    {
        return TestResult::Fail("AR9280 2.4/5 GHz permission not derived from the domain");
    }
    // DFS channels (52, 64) and non-channels are refused.
    for frequency in [5260, 5320, 5185, 5000, 2484] {
        if at(&domain, frequency) != Err(BringUpError::Policy) {
            return TestResult::Fail("AR9280 DFS or non-channel permission was authorized");
        }
    }
    domain.rules[1].flags = RegFlags::NO_IR;
    if at(&domain, 5180) != Err(BringUpError::Policy) {
        return TestResult::Fail("AR9280 NO_IR 5 GHz channel was authorized");
    }
    domain.rules[1].flags = RegFlags::empty();
    domain.rules[1].max_power_dbm = 17;
    if at(&domain, 5180).map(|p| p.ceiling) != Ok(34) {
        return TestResult::Fail("AR9280 5 GHz rule power did not bound the ceiling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_ar9280_dual_band_permission_refuses_dfs_and_no_ir
);
