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
/// -90/-130/-50 dBm on chains 0/1/2. The chan-info window returns the
/// 32-bit view with `S2_READ` clear and the 16-bit view with it set
/// (`ar9003_hw_tx_iq_cal_post_proc`'s two reads per word).
struct Model {
    values: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    chan: BTreeMap<u64, (u32, u32)>,
    now: u64,
    agc_stuck: bool,
    txiqcal_stuck: bool,
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
            chan: BTreeMap::new(),
            now: 0,
            agc_stuck: false,
            txiqcal_stuck: false,
        }
    }
    fn raw(&self, register: u64) -> u32 {
        self.values.get(&register).copied().unwrap_or(0)
    }
    fn wrote(&self, register: u64, value: u32) -> Option<usize> {
        self.writes.iter().position(|w| *w == (register, value))
    }
    /// The TX IQCAL status `CALIBRATED_GAINS_0` field for `nmeasurement`
    /// measurements, on the AR9485 map when `ar9485`.
    fn tx_iq_status(&mut self, ar9485: bool, nmeasurement: u32) {
        self.values.insert(
            if ar9485 {
                AR_PHY_TX_IQCAL_STATUS_B0_9485
            } else {
                AR_PHY_TX_IQCAL_STATUS_B0
            },
            nmeasurement << CALIBRATED_GAINS_0_SHIFT,
        );
    }
    /// One TX IQ calibration measurement's chan-info words for `chain`:
    /// the 32-bit view and the `S2_READ` 16-bit view per word.
    fn tx_iq_measurement(&mut self, chain: usize, im: usize, words: [u32; 6]) {
        for j in 0..3 {
            self.chan.insert(
                CHAN_INFO_TAB[chain] + (4 * (3 * im + j)) as u64,
                (words[2 * j], words[2 * j + 1]),
            );
        }
    }
}
impl RegisterIo for Model {
    fn read32(&mut self, register: u64) -> u32 {
        if let Some(&(view32, view16)) = self.chan.get(&register) {
            return if self.raw(AR_PHY_CHAN_INFO_MEMORY) & CHAN_INFO_TAB_S2_READ_MASK != 0 {
                view16
            } else {
                view32
            };
        }
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
        if (register == AR_PHY_TX_IQCAL_START || register == AR_PHY_TX_IQCAL_START_9485)
            && value & TX_IQCAL_START_DO_CAL != 0
            && !self.txiqcal_stuck
        {
            value &= !TX_IQCAL_START_DO_CAL;
        }
        if let Some(chain) = RXRF_AGC.iter().position(|r| *r == register) {
            // The peak-detect comparator reflects whichever CALDAC field
            // the band programs: bits 19-24 on 2 GHz, bits 9-14 on
            // 5 GHz (`ar9003_hw_manual_peak_cal`).
            let caldac = ((value >> 19) & 0x3f).max((value >> 9) & 0x3f);
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

/// `ar9003::Revision` for a test `AR_SREV` word (the `0x...ff` type-2
/// format of `ar9003/tests.rs`).
fn rev_for(srev: u32, chip: super::super::Chip) -> Revision {
    Revision::decode(srev, chip).expect("test SREV must decode")
}

fn identity(mask: u8) -> Identity {
    Identity {
        mac: [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56],
        eeprom_version: 2,
        template_version: 2,
        regulatory_domains: [0, 0],
        op_flags: 3,
        rx_chainmask: mask,
        tx_chainmask: mask,
        tx_gain: 0,
        rx_gain: 0,
    }
}

fn prepared(frequency: u16, mask: u8) -> Prepared {
    Prepared {
        frequency,
        modes_index: 4,
        carrier_leak_cal: true,
        selfgen_mask: mask & 3,
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
            tx_chainmask: mask,
        },
        ini_writes: 0,
    }
}

fn run(
    cal: &mut Calibration,
    io: &mut Model,
    chip_revision: &Revision,
    mask: u8,
    frequency: u16,
) -> Result<Report, BringUpError> {
    let prepared = prepared(frequency, mask);
    // SAFETY: the model is an exclusive, parked fake AR9300 with no DMA.
    ready(unsafe { cal.run(io, &identity(mask), chip_revision, &prepared) })
}

fn init() -> Result<(), &'static str> {
    let mut io = Model::new();
    let mut cal = Calibration::default();
    let revision = rev_for(0x001c_03ff, super::super::Chip::Ar9300);
    let report =
        run(&mut cal, &mut io, &revision, 7, 2412).map_err(|_| "AR9300 init cal refused")?;
    // The binary search settles one below each comparator threshold.
    if report.peak_caldac != [Some(36), Some(11), Some(49)]
        || (io.raw(RXRF_AGC[0]) >> 19) & 0x3f != 36
        || report.carrier_leak != Some(true)
        || report.default_nf != [-100, -110, -105]
        || report.tx_iq_cal.is_some()
        || report.tx_clcal.is_none()
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
    let mut periodic = Periodic::new(&revision, &report, IqTotals::default(), 0);
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
    let revision = rev_for(0x001c_03ff, super::super::Chip::Ar9300);
    if run(&mut cal, &mut io, &revision, 7, 5180) != Err(BringUpError::BadState)
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
    if run(&mut cal, &mut io, &revision, 7, 5180) != Err(BringUpError::Timeout)
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
        || iq_coefficients(u32::MAX, 64, 0x8000_0000)
            != Some(IqCoefficients {
                i: 65,
                q: 65,
                saturated: true,
            })
    {
        return TestResult::Fail("AR9300 IQ arithmetic boundary differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_calibration_refusals
);

fn smoke_ath9k_ar9003_tx_iq_enabled_cals() -> TestResult {
    // `ar9003_hw_init_cal_settings` (`:321-323`) per modeled chip.
    for (srev, chip, tx_iq_cal, tx_iq_on_agc_cal) in [
        (0x001c_03ff, super::super::Chip::Ar9300, true, false),
        (0x001c_04ff, super::super::Chip::Ar9580, true, false),
        (0x0024_01ff, super::super::Chip::Ar9485, true, true),
        (0x0028_02ff, super::super::Chip::Ar9462, true, true),
        (0x002c_02ff, super::super::Chip::Ar9565, true, true),
    ] {
        let revision = rev_for(srev, chip);
        let cals = enabled_cals(&revision);
        if cals.tx_iq_cal != tx_iq_cal || cals.tx_iq_on_agc_cal != tx_iq_on_agc_cal {
            return TestResult::Fail("ar9003_hw_init_cal_settings gating differs");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9003_tx_iq_enabled_cals
);

/// One TX IQ measurement's chan-info words: the fixture values whose
/// `ar9003_hw_calc_iq_corr` gives magnitude 24 / phase 3
/// (`iqc_coeff[0]` 3075). Unpacked inputs, all `i2_p` 1500:
/// `i2_m/iq_corr` a0_d0 150/200, a0_d1 150/300, a1_d0 100/100,
/// a1_d1 150/200.
const IQ_A: [u32; 6] = [0xc85d_c096, 0x960, 0x6412_c5dc, 0x5dc0, 0xdc09_6064, 0xc85];
/// A second measurement's words: magnitude 2 / phase -8, the outlier
/// `ar9003_hw_detect_outlier` replaces the first measurement with.
/// Unpacked inputs, all `i2_p` 1500: a0_d0 150/400, a0_d1 150/500,
/// a1_d0 100/300, a1_d1 100/200.
const IQ_B: [u32; 6] = [0x905d_c096, 0x961, 0x641f_45dc, 0x5dc0, 0xdc06_412c, 0xc85];

fn tx_iq_post_proc_9565() -> Result<(), &'static str> {
    let mut io = Model::new();
    let revision = rev_for(0x002c_02ff, super::super::Chip::Ar9565);
    io.tx_iq_status(false, 1);
    io.tx_iq_measurement(0, 0, IQ_A);
    let mut cal = Calibration::default();
    let report =
        run(&mut cal, &mut io, &revision, 1, 2412).map_err(|_| "AR9565 init cal refused")?;
    let Some(tx_iq_cal) = report.tx_iq_cal else {
        return Err("AR9565 TX IQ calibration did not complete");
    };
    // DELPT + ENABLE_TXIQ_CAL on the non-9485 map, the CORR_COEFF_B0
    // table write for the computed coefficient, the IQCORR enables, and
    // the saved TXIQCAL_DONE state; no B1/B2 table on a one-chain part.
    // The enablement precedes the AGC calibration.
    let (Some(delpt), Some(enable), Some(agc)) = (
        io.wrote(AR_PHY_TX_IQCAL_CONTROL_1, DELPT << 18),
        io.wrote(AR_PHY_TX_IQCAL_CONTROL_0, TXIQCAL_CONTROL_0_ENABLE_TXIQ_CAL),
        io.wrote(AR_PHY_AGC_CONTROL, AGC_CLC_SUCCESS | AGC_CAL),
    ) else {
        return Err("AR9565 TX IQ enablement write missing");
    };
    if tx_iq_cal.num_measures != [1, 0, 0]
        || tx_iq_cal.tx_corr_coeff[0][0] != 3075
        || io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B0, 3075).is_none()
        || io
            .writes
            .iter()
            .any(|w| w.0 == AR_PHY_TX_IQCAL_CORR_COEFF_B1 || w.0 == AR_PHY_TX_IQCAL_CORR_COEFF_B2)
        || io.raw(AR_PHY_TX_IQCAL_CONTROL_3) & TX_IQCAL_CONTROL_3_IQCORR_EN == 0
        || io.raw(RX_IQCAL_CORR[0]) & RX_IQCAL_CORR_B0_LOOPBACK_IQCORR_EN == 0
        || !(delpt < enable && enable < agc)
    {
        return Err("AR9565 TX IQ post-processing differs");
    }
    Ok(())
}

fn smoke_ath9k_ar9565_tx_iq_cal_post_proc() -> TestResult {
    match tx_iq_post_proc_9565() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_tx_iq_cal_post_proc
);

fn tx_iq_post_proc_9485() -> Result<(), &'static str> {
    let mut io = Model::new();
    let revision = rev_for(0x0024_01ff, super::super::Chip::Ar9485);
    io.tx_iq_status(true, 1);
    io.tx_iq_measurement(0, 0, IQ_A);
    let mut cal = Calibration::default();
    let report =
        run(&mut cal, &mut io, &revision, 1, 2412).map_err(|_| "AR9485 init cal refused")?;
    let Some(tx_iq_cal) = report.tx_iq_cal else {
        return Err("AR9485 TX IQ calibration did not complete");
    };
    // The AR9485 register map: DELPT, ENABLE_TXIQ_CAL and the CORR_COEFF
    // table all move; no non-9485 TX IQCAL register is written.
    if tx_iq_cal.num_measures != [1, 0, 0]
        || tx_iq_cal.tx_corr_coeff[0][0] != 3075
        || io
            .wrote(AR_PHY_TX_IQCAL_CONTROL_1_9485, DELPT << 18)
            .is_none()
        || io
            .wrote(
                AR_PHY_TX_IQCAL_CONTROL_0_9485,
                TXIQCAL_CONTROL_0_ENABLE_TXIQ_CAL,
            )
            .is_none()
        || io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B0_9485, 3075).is_none()
        || io.writes.iter().any(|w| {
            w.0 == AR_PHY_TX_IQCAL_CONTROL_1
                || w.0 == AR_PHY_TX_IQCAL_CONTROL_0
                || w.0 == AR_PHY_TX_IQCAL_CORR_COEFF_B0
                || w.0 == AR_PHY_TX_IQCAL_CORR_COEFF_B1
                || w.0 == AR_PHY_TX_IQCAL_CORR_COEFF_B2
        })
        || io.raw(AR_PHY_TX_IQCAL_CONTROL_3) & TX_IQCAL_CONTROL_3_IQCORR_EN == 0
        || io.raw(RX_IQCAL_CORR[0]) & RX_IQCAL_CORR_B0_LOOPBACK_IQCORR_EN == 0
    {
        return Err("AR9485 TX IQ post-processing differs");
    }
    Ok(())
}

fn smoke_ath9k_ar9485_tx_iq_cal_post_proc() -> TestResult {
    match tx_iq_post_proc_9485() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9485_tx_iq_cal_post_proc
);

fn tx_iq_outlier_and_reload() -> Result<(), &'static str> {
    let mut io = Model::new();
    let revision = rev_for(0x001c_03ff, super::super::Chip::Ar9300);
    io.tx_iq_status(false, 2);
    for chain in 0..3 {
        io.tx_iq_measurement(chain, 0, IQ_A);
        io.tx_iq_measurement(chain, 1, IQ_B);
    }
    let Some(data) = tx_iq_cal_post_proc(&mut io, &revision, 7).map_err(|_| "post-proc failed")?
    else {
        return Err("AR9300 TX IQ post-processing failed");
    };
    // Outlier detection rewrote both measurements to mag 2 / phs 3
    // (`iqc_coeff` 259); each CORR_COEFF register carries two
    // measurements, even in the `00` field and odd in the `01` field.
    // The odd write is a read-modify-write (`REG_RMW_FIELD`), so it
    // carries the even field the first write programmed:
    // `259 | (259 << 14)`, not `259 << 14` alone.
    if data.num_measures != [2, 2, 2]
        || data.tx_corr_coeff[0] != [259, 259, 259]
        || data.tx_corr_coeff[1] != [259, 259, 259]
        || io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B0, 259).is_none()
        || io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B1, 259).is_none()
        || io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B2, 259).is_none()
        || io
            .wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B0, 259 | (259 << 14))
            .is_none()
        || io
            .wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B1, 259 | (259 << 14))
            .is_none()
        || io
            .wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B2, 259 | (259 << 14))
            .is_none()
        || io.raw(AR_PHY_TX_IQCAL_CONTROL_3) & TX_IQCAL_CONTROL_3_IQCORR_EN == 0
        || io.raw(RX_IQCAL_CORR[0]) & RX_IQCAL_CORR_B0_LOOPBACK_IQCORR_EN == 0
    {
        return Err("AR9300 TX IQ outlier detection differs");
    }
    // Reload re-applies the same tables and re-enables IQCORR.
    let mut io = Model::new();
    tx_iq_cal_reload(&mut io, &revision, 7, &data).map_err(|_| "reload failed")?;
    if io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B0, 259).is_none()
        || io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B1, 259).is_none()
        || io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B2, 259).is_none()
        || io
            .wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B0, 259 | (259 << 14))
            .is_none()
        || io.raw(AR_PHY_TX_IQCAL_CONTROL_3) & TX_IQCAL_CONTROL_3_IQCORR_EN == 0
        || io.raw(RX_IQCAL_CORR[0]) & RX_IQCAL_CORR_B0_LOOPBACK_IQCORR_EN == 0
    {
        return Err("AR9300 TX IQ reload differs");
    }
    // On AR9485 the same data reloads only chain 0's B0 table.
    let mut io = Model::new();
    let revision = rev_for(0x0024_01ff, super::super::Chip::Ar9485);
    tx_iq_cal_reload(&mut io, &revision, 1, &data).map_err(|_| "9485 reload failed")?;
    if io.wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B0_9485, 259).is_none()
        || io
            .wrote(AR_PHY_TX_IQCAL_CORR_COEFF_B0_9485, 259 | (259 << 14))
            .is_none()
        || io
            .writes
            .iter()
            .any(|w| w.0 == AR_PHY_TX_IQCAL_CORR_COEFF_B1 || w.0 == AR_PHY_TX_IQCAL_CORR_COEFF_B2)
    {
        return Err("AR9485 TX IQ reload differs");
    }
    Ok(())
}

fn smoke_ath9k_ar9003_tx_iq_cal_outlier_and_reload() -> TestResult {
    match tx_iq_outlier_and_reload() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9003_tx_iq_cal_outlier_and_reload
);

fn rx_iq_saturation_abort() -> Result<(), &'static str> {
    // Totals that saturate chain 0's coefficients: (65, 65) is i=-63,
    // q=-63. The periodic collection must add nothing, so the CAL_MEAS
    // registers read zero.
    let totals = IqTotals {
        power_i: [u32::MAX, 0, 0],
        power_q: [64, 0, 0],
        correlation: [i32::MIN, 0, 0],
    };
    // AR9300 writes the saturated coefficients and enables the correction.
    let mut io = Model::new();
    for meas in CAL_MEAS {
        io.values.insert(meas, 0);
        io.values.insert(meas + 4, 0);
        io.values.insert(meas + 8, 0);
    }
    let mut cal = Calibration::default();
    let revision = rev_for(0x001c_03ff, super::super::Chip::Ar9300);
    let report =
        run(&mut cal, &mut io, &revision, 7, 2412).map_err(|_| "AR9300 init cal refused")?;
    let mut periodic = Periodic::new(&revision, &report, totals, 0);
    let tick = periodic
        .tick(&mut io, 1000)
        .map_err(|_| "AR9300 IQ tick failed")?;
    if tick.iq != Some([Some((65, 65)), None, None])
        || !periodic.caldone()
        || (io.raw(RX_IQCAL_CORR[0]) >> 7) & 0x7f != 65
        || io.raw(RX_IQCAL_CORR[0]) & IQCORR_ENABLE == 0
    {
        return Err("AR9300 saturated IQ coefficients differ");
    }
    // AR9565 aborts the whole calibration on the saturated chain: no
    // coefficient write and no enable, but the calibration is done.
    let mut io = Model::new();
    for meas in CAL_MEAS {
        io.values.insert(meas, 0);
        io.values.insert(meas + 4, 0);
        io.values.insert(meas + 8, 0);
    }
    let mut cal = Calibration::default();
    let revision = rev_for(0x002c_02ff, super::super::Chip::Ar9565);
    let report =
        run(&mut cal, &mut io, &revision, 1, 2412).map_err(|_| "AR9565 init cal refused")?;
    let mut periodic = Periodic::new(&revision, &report, totals, 0);
    let tick = periodic
        .tick(&mut io, 1000)
        .map_err(|_| "AR9565 IQ tick failed")?;
    if tick.iq != Some([None, None, None])
        || !periodic.caldone()
        || periodic.iq_state() != CalState::Done
        || (io.raw(RX_IQCAL_CORR[0]) >> 7) & 0x7f != 0
        || io.raw(RX_IQCAL_CORR[0]) & 0x7f != 0
        || io.raw(RX_IQCAL_CORR[0]) & IQCORR_ENABLE != 0
    {
        return Err("AR9565 saturated IQ calibration did not abort");
    }
    Ok(())
}

fn smoke_ath9k_ar9565_rx_iq_saturation_abort() -> TestResult {
    match rx_iq_saturation_abort() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_rx_iq_saturation_abort
);

fn tx_iq_cal_run_paths() -> Result<(), &'static str> {
    // Success on the non-9485 map: a forced TX gain is cleared, the TX
    // IQ calibration is triggered and completes.
    let mut io = Model::new();
    io.values.insert(AR_PHY_TX_FORCED_GAIN, TXGAIN_FORCE);
    match ready(tx_iq_cal_run(&mut io, false)) {
        Ok(true) => {}
        _ => return Err("AR9300 TX IQ cal run did not complete"),
    }
    if io.raw(AR_PHY_TX_FORCED_GAIN) & TXGAIN_FORCE != 0
        || io
            .wrote(AR_PHY_TX_IQCAL_START, TX_IQCAL_START_DO_CAL)
            .is_none()
    {
        return Err("AR9300 TX IQ cal run trigger differs");
    }
    // A stuck TX IQ calibration reports incomplete, not an error:
    // `ar9003_hw_init_cal_soc` falls back to the AGC calibration alone.
    let mut io = Model::new();
    io.txiqcal_stuck = true;
    match ready(tx_iq_cal_run(&mut io, false)) {
        Ok(false) => {}
        _ => return Err("stuck TX IQ cal run did not report incomplete"),
    }
    // The AR9485 map moves the trigger register; no non-9485 TX IQCAL
    // register is written.
    let mut io = Model::new();
    match ready(tx_iq_cal_run(&mut io, true)) {
        Ok(true) => {}
        _ => return Err("AR9485 TX IQ cal run did not complete"),
    }
    if io
        .wrote(AR_PHY_TX_IQCAL_START_9485, TX_IQCAL_START_DO_CAL)
        .is_none()
        || io.writes.iter().any(|w| w.0 == AR_PHY_TX_IQCAL_START)
    {
        return Err("AR9485 TX IQ cal run used the wrong map");
    }
    Ok(())
}

fn smoke_ath9k_ar9003_tx_iq_cal_run() -> TestResult {
    match tx_iq_cal_run_paths() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9003_tx_iq_cal_run
);

fn dynamic_osdac_selection_paths() -> Result<(), &'static str> {
    // In-range offsets (15, inside 7..24) on all chains: one loop
    // iteration, OSDAC stays 0, the initial AGC cal plus one loop AGC
    // cal, and the end state (OFFSET_CAL cleared, PHY active, TX IQ
    // calibration re-enabled).
    let mut io = Model::new();
    for bb3 in BB3 {
        io.values.insert(bb3, (15 << 26) | (15 << 21));
    }
    let revision = rev_for(0x001c_03ff, super::super::Chip::Ar9300);
    match ready(dynamic_osdac_selection(&mut io, &revision, true)) {
        Ok(true) => {}
        _ => return Err("AR9300 dynamic OSDAC selection did not complete"),
    }
    if io.raw(BB1[0]) >> 30 != 0
        || io.raw(BB1[1]) >> 30 != 0
        || io.raw(BB1[2]) >> 30 != 0
        || io
            .writes
            .iter()
            .filter(|w| w.0 == AR_PHY_AGC_CONTROL && w.1 & AGC_CAL != 0)
            .count()
            != 2
        || io.raw(AR_PHY_AGC_CONTROL) & AGC_OFFSET_CAL != 0
        || io.raw(AR_PHY_ACTIVE) & AR_PHY_ACTIVE_EN == 0
        || io.raw(AR_PHY_TX_IQCAL_CONTROL_0) & TXIQCAL_CONTROL_0_ENABLE_TXIQ_CAL == 0
    {
        return Err("AR9300 dynamic OSDAC selection in-range differs");
    }
    // Out-of-range offsets (0, below 7) on all chains: OSDAC climbs
    // 0 -> 3 over four iterations, five AGC cals in total.
    let mut io = Model::new();
    match ready(dynamic_osdac_selection(&mut io, &revision, true)) {
        Ok(true) => {}
        _ => return Err("AR9300 dynamic OSDAC selection did not complete"),
    }
    if io.raw(BB1[0]) != 3 << 30
        || io.raw(BB1[1]) != 3 << 30
        || io.raw(BB1[2]) != 3 << 30
        || io
            .writes
            .iter()
            .filter(|w| w.0 == AR_PHY_AGC_CONTROL && w.1 & AGC_CAL != 0)
            .count()
            != 5
    {
        return Err("AR9300 dynamic OSDAC selection out-of-range differs");
    }
    // A stuck AGC calibration fails the selection.
    let mut io = Model::new();
    io.agc_stuck = true;
    match ready(dynamic_osdac_selection(&mut io, &revision, true)) {
        Ok(false) => {}
        _ => return Err("stuck dynamic OSDAC selection did not fail"),
    }
    // The AR9485 map moves the TX IQCAL control register; no non-9485
    // TX IQCAL register is written.
    let mut io = Model::new();
    for bb3 in BB3 {
        io.values.insert(bb3, (15 << 26) | (15 << 21));
    }
    let revision = rev_for(0x0024_01ff, super::super::Chip::Ar9485);
    match ready(dynamic_osdac_selection(&mut io, &revision, true)) {
        Ok(true) => {}
        _ => return Err("AR9485 dynamic OSDAC selection did not complete"),
    }
    if io.raw(AR_PHY_TX_IQCAL_CONTROL_0_9485) & TXIQCAL_CONTROL_0_ENABLE_TXIQ_CAL == 0
        || io.writes.iter().any(|w| w.0 == AR_PHY_TX_IQCAL_CONTROL_0)
    {
        return Err("AR9485 dynamic OSDAC selection used the wrong map");
    }
    Ok(())
}

fn smoke_ath9k_ar9003_dynamic_osdac_selection() -> TestResult {
    match dynamic_osdac_selection_paths() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9003_dynamic_osdac_selection
);

fn fast_channel_change(
    cal: &mut Calibration,
    io: &mut Model,
    revision: &Revision,
    mask: u8,
    frequency: u16,
    saved: &Report,
) -> Result<Report, BringUpError> {
    let prepared = prepared(frequency, mask);
    // SAFETY: the model is an exclusive, parked fake AR9300 with no DMA.
    ready(unsafe { cal.fast_channel_change(io, &identity(mask), revision, &prepared, saved) })
}

fn fast_channel_change_reload() -> Result<(), &'static str> {
    let mut io = Model::new();
    let revision = rev_for(0x001c_03ff, super::super::Chip::Ar9300);
    // Distinctive carrier-leak table entries for the save to keep.
    io.values.insert(CL_TAB[0], 0x1111_1111);
    io.values.insert(CL_TAB[1] + 20, 0x2222_2222);
    io.values.insert(CL_TAB[2] + 60, 0x3333_3333);
    let mut cal = Calibration::default();
    let mut saved =
        run(&mut cal, &mut io, &revision, 7, 2412).map_err(|_| "AR9300 init cal refused")?;
    // Saved TX IQ coefficients from a direct post-processing, as the
    // outlier test builds them.
    let mut gen = Model::new();
    gen.tx_iq_status(false, 2);
    for chain in 0..3 {
        gen.tx_iq_measurement(chain, 0, IQ_A);
        gen.tx_iq_measurement(chain, 1, IQ_B);
    }
    let data = match tx_iq_cal_post_proc(&mut gen, &revision, 7) {
        Ok(Some(data)) => data,
        _ => return Err("AR9300 TX IQ post-processing failed"),
    };
    saved.tx_iq_cal = Some(data);
    let saved_cl = match saved.tx_clcal {
        Some(saved_cl) => saved_cl,
        None => return Err("AR9300 carrier-leak table was not saved"),
    };
    if saved_cl.table[0][0] != 0x1111_1111
        || saved_cl.table[1][5] != 0x2222_2222
        || saved_cl.table[2][15] != 0x3333_3333
    {
        return Err("AR9300 carrier-leak table save differs");
    }
    // The reload path: saved coefficients re-applied, saved table
    // re-written, no AGC calibration (nothing forced it), no peak cal.
    let mark = io.writes.len();
    let mut fast = Calibration::default();
    let report = fast_channel_change(&mut fast, &mut io, &revision, 7, 2437, &saved)
        .map_err(|_| "AR9300 fast channel change refused")?;
    let phase = &io.writes[mark..];
    if report.frequency_mhz != 2437
        || report.tx_iq_cal != Some(data)
        || report.tx_clcal != Some(saved_cl)
        || report.peak_caldac != [None, None, None]
        || report.default_nf != [-100, -110, -105]
        || fast.state() != State::Ready
        || phase
            .iter()
            .any(|w| w.0 == AR_PHY_AGC_CONTROL && w.1 & AGC_CAL != 0)
        || !phase.contains(&(CL_TAB[0], 0x1111_1111))
        || !phase.contains(&(CL_TAB[1] + 20, 0x2222_2222))
        || !phase.contains(&(CL_TAB[2] + 60, 0x3333_3333))
        || !phase.contains(&(AR_PHY_TX_IQCAL_CORR_COEFF_B0, 259))
        || !phase.contains(&(AR_PHY_TX_IQCAL_CORR_COEFF_B1, 259))
        || !phase.contains(&(AR_PHY_TX_IQCAL_CORR_COEFF_B2, 259))
        || !phase.contains(&(AR_PHY_TX_IQCAL_CORR_COEFF_B0, 259 | (259 << 14)))
        || !phase.contains(&(AR_PHY_TX_IQCAL_CORR_COEFF_B1, 259 | (259 << 14)))
        || !phase.contains(&(AR_PHY_TX_IQCAL_CORR_COEFF_B2, 259 | (259 << 14)))
    {
        return Err("AR9300 fast channel change reload differs");
    }
    Ok(())
}

fn smoke_ath9k_ar9300_fast_channel_change_reload() -> TestResult {
    match fast_channel_change_reload() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_fast_channel_change_reload
);

fn fast_channel_change_fresh() -> Result<(), &'static str> {
    let mut io = Model::new();
    let revision = rev_for(0x002c_02ff, super::super::Chip::Ar9565);
    io.tx_iq_status(false, 1);
    io.tx_iq_measurement(0, 0, IQ_A);
    io.values.insert(CL_TAB[0], 0x1111_1111);
    io.values.insert(CL_TAB[0] + 20, 0x2222_2222);
    io.values.insert(CL_TAB[0] + 60, 0x3333_3333);
    let mut cal = Calibration::default();
    let saved =
        run(&mut cal, &mut io, &revision, 1, 2412).map_err(|_| "AR9565 init cal refused")?;
    let tx_iq_cal = match saved.tx_iq_cal {
        Some(tx_iq_cal) => tx_iq_cal,
        None => return Err("AR9565 TX IQ calibration did not complete"),
    };
    if tx_iq_cal.tx_corr_coeff[0][0] != 3075 {
        return Err("AR9565 TX IQ coefficient differs");
    }
    // The fresh path across bands: `TX_IQ_ON_AGC_CAL` re-runs the AGC
    // calibration and the TX IQ post-processing, and the saved table is
    // still re-written.
    let mark = io.writes.len();
    let mut fast = Calibration::default();
    let report = fast_channel_change(&mut fast, &mut io, &revision, 1, 5180, &saved)
        .map_err(|_| "AR9565 fast channel change refused")?;
    let phase = &io.writes[mark..];
    if report.frequency_mhz != 5180
        || !report.five_ghz
        || report.tx_iq_cal != Some(tx_iq_cal)
        || report.peak_caldac != [Some(36), None, None]
        || report.default_nf != [-100, -115, -105]
        || fast.state() != State::Ready
        || !phase
            .iter()
            .any(|w| w.0 == AR_PHY_AGC_CONTROL && w.1 & AGC_CAL != 0)
        || !phase.contains(&(CL_TAB[0], 0x1111_1111))
        || !phase.contains(&(CL_TAB[0] + 20, 0x2222_2222))
        || !phase.contains(&(CL_TAB[0] + 60, 0x3333_3333))
    {
        return Err("AR9565 fast channel change differs");
    }
    Ok(())
}

fn smoke_ath9k_ar9565_fast_channel_change() -> TestResult {
    match fast_channel_change_fresh() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_fast_channel_change
);

fn fast_channel_change_refusals() -> Result<(), &'static str> {
    let mut io = Model::new();
    let revision = rev_for(0x001c_03ff, super::super::Chip::Ar9300);
    let mut cal = Calibration::default();
    let saved =
        run(&mut cal, &mut io, &revision, 7, 2412).map_err(|_| "AR9300 init cal refused")?;
    // Same channel: refused before any write.
    let mark = io.writes.len();
    let mut fast = Calibration::default();
    if fast_channel_change(&mut fast, &mut io, &revision, 7, 2412, &saved)
        != Err(BringUpError::BadState)
        || fast.state() != State::New
        || io.writes.len() != mark
    {
        return Err("AR9300 fast channel change ran on the same channel");
    }
    // Inactive PHY: refused before any write.
    let mut io = Model::new();
    let mut fast = Calibration::default();
    let mark = io.writes.len();
    if fast_channel_change(&mut fast, &mut io, &revision, 7, 5180, &saved)
        != Err(BringUpError::BadState)
        || fast.state() != State::New
        || io.writes.len() != mark
    {
        return Err("AR9300 fast channel change ran on an inactive PHY");
    }
    Ok(())
}

fn smoke_ath9k_ar9300_fast_channel_change_refusals() -> TestResult {
    match fast_channel_change_refusals() {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_fast_channel_change_refusals
);
