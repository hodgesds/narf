use super::*;
use crate::ath9k::ar9003::power::{Plan, RATES};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Self-completing AR9300 model: the AGC/IQ/NF engines finish on the next
/// read; a peak-detect comparator per chain reports `AGC_OUT` once the
/// CALDAC reaches its threshold; a completed NF measurement reports
/// -90/-130/-50 dBm on chains 0/1/2.
struct Model {
    values: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    now: u64,
    agc_stuck: bool,
}
const THRESHOLD: [u32; 3] = [37, 12, 50];
impl Model {
    fn new() -> Self {
        let mut values = BTreeMap::new();
        for (register, value) in [
            (AR_DIAG_SW, AR_DIAG_RX_PARK),
            (AR_PHY_RX_DELAY, 1000),
            (AR_PHY_CL_CAL_CTL, AR_PHY_CL_CAL_ENABLE),
            (AR_PHY_AGC_CONTROL, AGC_CLC_SUCCESS),
            (CAL_MEAS[0], 20000),
            (CAL_MEAS[0] + 4, 16000),
            (CAL_MEAS[0] + 8, 0xffff_f000),
            (CAL_MEAS[1], 21000),
            (CAL_MEAS[1] + 4, 20000),
            (CAL_MEAS[1] + 8, 500),
            (CAL_MEAS[2], 4000),
        ] {
            values.insert(register, value);
        }
        Self {
            values,
            writes: Vec::new(),
            now: 0,
            agc_stuck: false,
        }
    }
    fn raw(&self, register: u64) -> u32 {
        self.values.get(&register).copied().unwrap_or(0)
    }
    fn wrote(&self, register: u64, value: u32) -> Option<usize> {
        self.writes.iter().position(|w| *w == (register, value))
    }
}
impl RegisterIo for Model {
    fn read32(&mut self, register: u64) -> u32 {
        let mut value = self.raw(register);
        if register == AR_PHY_AGC_CONTROL {
            if value & AGC_CAL != 0 && !self.agc_stuck {
                value &= !AGC_CAL;
            }
            if value & AGC_NF != 0 {
                if value & AGC_ENABLE_NF != 0 {
                    for (nf, dbm) in NF_REGS.iter().zip([-90i32, -130, -50]) {
                        let old = self.raw(*nf) & !0x1ff0_0000;
                        self.values
                            .insert(*nf, old | (((dbm as u32) & 0x1ff) << 20));
                    }
                }
                value &= !AGC_NF;
            }
        }
        if register == AR_PHY_TIMING4 {
            value &= !AR_PHY_TIMING4_DO_CAL;
        }
        if let Some(chain) = RXRF_AGC.iter().position(|r| *r == register) {
            let caldac = (value >> 19) & 0x3f;
            value = (value & !0x4) | (u32::from(caldac >= THRESHOLD[chain]) << 2);
        }
        self.values.insert(register, value);
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
        Poll::Pending => panic!("self-completing AR9300 model unexpectedly waited"),
    }
}

fn identity() -> Identity {
    Identity {
        mac: [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56],
        eeprom_version: 2,
        template_version: 2,
        regulatory_domains: [0, 0],
        op_flags: 3,
        rx_chainmask: 7,
        tx_chainmask: 7,
        tx_gain: 0,
        rx_gain: 0,
    }
}

fn prepared(frequency: u16) -> Prepared {
    Prepared {
        frequency,
        modes_index: 4,
        carrier_leak_cal: true,
        selfgen_mask: 3,
        power: Plan {
            frequency,
            targets: [0; RATES],
            max_power_level: 0,
            correction: [0; 3],
            temperature: [0; 3],
            voltage: [0; 3],
            nf_cal: [-100, 0, -105],
            nf_power: [0; 3],
            temp_slope: 0,
            tx_chainmask: 7,
        },
        ini_writes: 0,
    }
}

fn run(cal: &mut Calibration, io: &mut Model, prepared: &Prepared) -> Result<Report, BringUpError> {
    // SAFETY: the model is an exclusive, parked fake AR9300 with no DMA.
    ready(unsafe { cal.run(io, &identity(), prepared) })
}

fn init() -> Result<(), &'static str> {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    let report = run(&mut cal, &mut io, &prepared(2412)).map_err(|_| "AR9300 init cal refused")?;
    // The binary search settles one below each comparator threshold.
    if report.peak_caldac != [Some(36), Some(11), Some(49)]
        || (io.raw(RXRF_AGC[0]) >> 19) & 0x3f != 36
        || report.carrier_leak != Some(true)
        || report.default_nf != [-100, -110, -105]
        || cal.state() != State::Ready
        || cal.report() != Some(report)
    {
        return Err("AR9300 peak cal / CLC / default NF report differs");
    }
    // init_bb activates before calibrating; the CL bracket parks the PHY,
    // forces RX_DELAY, then restores the INI delay after the AGC cal.
    let (Some(active), Some(cl), Some(delpt), Some(forced), Some(agc), Some(restored)) = (
        io.wrote(AR_PHY_ACTIVE, 1),
        io.wrote(AR_PHY_CL_CAL_CTL, AR_PHY_CL_CAL_ENABLE),
        io.wrote(AR_PHY_TX_IQCAL_CONTROL_1, DELPT << 18),
        io.wrote(AR_PHY_RX_DELAY, AR_PHY_RX_DELAY_DELAY),
        io.wrote(AR_PHY_AGC_CONTROL, AGC_CLC_SUCCESS | AGC_CAL),
        io.wrote(AR_PHY_RX_DELAY, 1000),
    ) else {
        return Err("AR9300 init_cal_pcoem write missing");
    };
    if !(active < cl && cl < delpt && delpt < forced && forced < agc && agc < restored) {
        return Err("AR9300 init order differs from ar9003_hw_init_cal_pcoem");
    }
    // Chain masks written for calibration and again for runtime; the IQ
    // mismatch calibration is left running with PER_MAX_LOG_COUNT.
    if io
        .writes
        .iter()
        .filter(|w| **w == (AR_SELFGEN_MASK, 3))
        .count()
        != 2
        || io.raw(AR_PHY_CAL_CHAINMASK) != 7
        || io.raw(AR_PHY_TIMING4) & 0xf000 != 10 << 12
        || io.wrote(AR_PHY_CALMODE, 0).is_none_or(|m| m < restored)
    {
        return Err("AR9300 chain masks / IQ kick-off differ");
    }

    // Reset tail: history privNF loaded, -50 restored, NF started (update).
    let mut periodic = Periodic::new(&report, IqTotals::default(), 0);
    periodic
        .start(&mut io)
        .map_err(|_| "AR9300 reset NF load failed")?;
    if io.wrote(NF_REGS[0], nf_field(-100)).is_none()
        || io.wrote(NF_REGS[1], nf_field(-110)).is_none()
        || io.raw(NF_REGS[2]) & 0x1ff != nf_field(-50)
        || io.raw(AR_PHY_AGC_CONTROL) & AGC_NO_UPDATE_NF != 0
        || !periodic.nfcal_pending()
    {
        return Err("AR9300 reset-tail loadnf/start_nfcal differs");
    }

    // First short calibration completes the IQ cal over three chains.
    let tick = periodic.tick(&mut io, 1000).map_err(|_| "IQ tick failed")?;
    let expected = [Some((58, 16)), Some((122, 3)), None];
    if !tick.shortcal
        || tick.longcal
        || tick.iq != Some(expected)
        || !periodic.caldone()
        || periodic.iq_state() != CalState::Done
        || (io.raw(RX_IQCAL_CORR[0]) >> 7) & 0x7f != 58
        || io.raw(RX_IQCAL_CORR[0]) & IQCORR_ENABLE == 0
        || io.raw(RX_IQCAL_CORR[1]) & 0x7f != 3
    {
        return Err("AR9300 ar9003_hw_iqcalibrate coefficients differ");
    }
    // Long calibration: sanitized NF into the history, reloaded, restarted
    // without updating the baseband.
    let tick = periodic
        .tick(&mut io, 30_000)
        .map_err(|_| "NF tick failed")?;
    if !tick.longcal
        || tick.noise_floor != Some(-90)
        || periodic.private_nf() != [-90, -110, -60]
        || io.raw(AR_PHY_AGC_CONTROL) & AGC_NO_UPDATE_NF == 0
    {
        return Err("AR9300 long calibration NF history/limits differ");
    }
    // The 20 min restart (on a long-calibration tick here) reopens and
    // restarts the IQ cal; Linux's totals accumulate across runs.
    let tick = periodic
        .tick(&mut io, 1_230_000)
        .map_err(|_| "restart failed")?;
    if periodic.caldone() || tick.iq.is_some() || periodic.iq_state() != CalState::Running {
        return Err("AR9300 reset_calvalid did not restart the IQ cal");
    }
    let tick = periodic
        .tick(&mut io, 1_231_000)
        .map_err(|_| "re-cal failed")?;
    if tick.iq != Some(expected) || periodic.totals().power_i[0] != 40000 {
        return Err("AR9300 IQ totals did not accumulate as Linux");
    }
    Ok(())
}

fn smoke_ath9k_ar9300_init_and_periodic_calibration() -> TestResult {
    match init() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_init_and_periodic_calibration
);

fn smoke_ath9k_ar9300_calibration_refusals() -> TestResult {
    // An active PHY is refused before any write.
    let mut io = Model::new();
    io.values.insert(AR_PHY_ACTIVE, 1);
    let mut cal = Calibration::default();
    if run(&mut cal, &mut io, &prepared(5180)) != Err(BringUpError::BadState)
        || !io.writes.is_empty()
        || cal.state() != State::New
    {
        return TestResult::Fail("AR9300 calibration ran on an active PHY");
    }
    // A stuck AGC calibration still runs the peak cal, restores RX_DELAY,
    // then fails the attempt.
    let mut io = Model::new();
    io.agc_stuck = true;
    let mut cal = Calibration::default();
    if run(&mut cal, &mut io, &prepared(5180)) != Err(BringUpError::Timeout)
        || cal.state() != State::Failed
        || io.wrote(AR_PHY_RX_DELAY, 1000).is_none()
        || (io.raw(RXRF_AGC[0]) >> 9) & 0x3f == 0
        || io.wrote(AR_PHY_CALMODE, 0).is_some()
    {
        return TestResult::Fail("AR9300 AGC timeout not handled as Linux");
    }
    // Linux skips the update only when a denominator is zero:
    // (0/2 + 63/2) / 256 == 0.
    if iq_coefficients(0, 63, 1).is_some()
        || iq_coefficients(u32::MAX, 64, 0x8000_0000) != Some((65, 65))
    {
        return TestResult::Fail("AR9300 IQ arithmetic boundary differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_calibration_refusals
);
