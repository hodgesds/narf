use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");

pub(in crate::rtw89) struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    scenario: u8,
    hash: u64,
    count: u32,
    now: u64,
    ready_at: u64,
    command: u32,
    active_command: bool,
    path: usize,
    group: u32,
    bias: [u8; 2],
    admissions: usize,
    operations: usize,
    delays: usize,
    deny: Option<usize>,
    fail: Option<usize>,
    pending: Option<usize>,
    ignore: Option<u32>,
    stuck: bool,
    rx_stuck: bool,
    admitted: bool,
    resumed: bool,
    ended: bool,
}
impl Model {
    pub(in crate::rtw89) fn new(seed: u8, scenario: u8) -> Self {
        let word = u32::from(seed) * 0x01010101;
        Self {
            words: vec![word; 0x20000 / 4],
            rf: core::array::from_fn(|_| vec![word & 0xfffff; 0x10100]),
            scenario,
            hash: 14695981039346656037,
            count: 0,
            now: 0,
            ready_at: 0,
            command: 0,
            active_command: false,
            path: 0,
            group: 0,
            bias: [0; 2],
            admissions: 0,
            operations: 0,
            delays: 0,
            deny: None,
            fail: None,
            pending: None,
            ignore: None,
            stuck: false,
            rx_stuck: false,
            admitted: false,
            resumed: false,
            ended: false,
        }
    }
    pub(in crate::rtw89) fn with_registers(
        words: Vec<u32>,
        rf: [Vec<u32>; 2],
        now: u64,
    ) -> Result<Self, Error> {
        if words.len() != 0x20000 / 4 || rf.iter().any(|path| path.len() != 0x10100) {
            return Err(Error::Table);
        }
        let mut model = Self::new(0, 0);
        model.words = words;
        model.rf = rf;
        model.now = now;
        Ok(model)
    }
    pub(in crate::rtw89) fn into_registers(self) -> (Vec<u32>, [Vec<u32>; 2], u64) {
        (self.words, self.rf, self.now)
    }
    fn record(&mut self, values: &[u32]) {
        self.count += 1;
        for value in values {
            for byte in value.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        assert!(self.admitted, "IQK access bypassed current RF admission");
        self.admitted = false;
        let op = self.operations;
        self.operations += 1;
        if self.fail == Some(op) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn failed_command(&self) -> bool {
        let op = (self.command >> 8) & 15;
        match self.scenario {
            3 => self.path == 0 && op == 1,
            4 => self.path == 1 && op == 8 && self.group == 2,
            5 => self.path == 0 && op == 11 && self.group == 3,
            6 => self.path == 1 && op == 14,
            7 => self.path == 0 && op == 3,
            _ => false,
        }
    }
    fn selector(&self, address: u32, mask: u32) -> u32 {
        (self.words[(0x10000 + address) as usize / 4] & mask) >> mask.trailing_zeros()
    }
}
impl power::Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.access()?;
        let mut value = self.words[address as usize / 4];
        match address - 0x10000 {
            0xbff8 => {
                value = if self.active_command && !self.stuck && self.now >= self.ready_at {
                    0x55
                } else {
                    0
                }
            }
            R_NCTL_N1 if self.active_command && !self.stuck && self.now >= self.ready_at => {
                value = (value & !0xff) | 0x55;
            }
            R_NCTL_RPT => {
                value = (value & !B_NCTL_RPT_FLG)
                    | if self.failed_command() {
                        B_NCTL_RPT_FLG
                    } else {
                        0
                    }
            }
            _ => {}
        }
        Ok(value)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.access()?;
        self.record(&[4, address, value]);
        if self.ignore == Some(address - 0x10000) {
            return Ok(());
        }
        self.words[address as usize / 4] = value;
        if address == 0x10000 + R_NCTL_N1 && value & 0xff == 0 {
            self.active_command = false;
        }
        if address == 0x10000 + R_NCTL_CFG {
            self.active_command = true;
            self.command = value;
            self.path = usize::from(value & 0x20 != 0);
            let mask = if (value >> 8) & 15 == 11 {
                B_CFIR_LUT_GP_V1
            } else {
                B_CFIR_LUT_GP
            };
            self.group = self.selector(R_CFIR_LUT + ((self.path as u32) << 8), mask);
            self.ready_at = self.now + if self.scenario == 8 { 3 } else { 0 };
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.access().unwrap();
        let delay = self.delays;
        self.delays += 1;
        self.record(&[8, us as u32, 0]);
        if self.pending == Some(delay) {
            core::future::pending::<()>().await;
        }
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        let n = self.admissions;
        self.admissions += 1;
        if self.deny == Some(n) {
            return Err(Error::Policy);
        }
        self.admitted = true;
        Ok(())
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        self.access()?;
        let mut value = self.rf[usize::from(path)][address as usize];
        if address == RR_MOD && mask == RR_MOD_MASK && self.rx_stuck {
            value = 2 << mask.trailing_zeros();
        }
        if address == RR_TXMO {
            let bad =
                self.scenario == 2 || (self.scenario == 1 && self.bias[usize::from(path)] < 3);
            value = (if bad { 1 } else { 0x10 } << RR_TXMO_COI.trailing_zeros())
                | (0x11 << RR_TXMO_COQ.trailing_zeros());
        }
        if address == RR_LOKVB {
            value =
                (0x20 << RR_LOKVB_COI.trailing_zeros()) | (0x21 << RR_LOKVB_COQ.trailing_zeros());
        }
        value = (value & mask) >> mask.trailing_zeros();
        self.record(&[32, u32::from(path), address, mask, value]);
        Ok(value)
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.access()?;
        let old = self.rf[usize::from(path)][address as usize];
        self.rf[usize::from(path)][address as usize] =
            (old & !mask) | ((value << mask.trailing_zeros()) & mask);
        if address == RR_LUTWD0 && mask == RFREG_MASK {
            self.bias[usize::from(path)] = value as u8;
        }
        self.record(&[36, u32::from(path), address, mask, value]);
        Ok(())
    }
    async fn begin(&mut self, kind: Kind) -> Result<(), Error> {
        self.access()?;
        self.record(&[48, 0, if kind == Kind::IqkPath { 2 } else { 0 }]);
        Ok(())
    }
    async fn end(&mut self, kind: Kind) -> Result<(), Error> {
        self.access()?;
        self.record(&[48, 0, if kind == Kind::IqkPath { 3 } else { 1 }]);
        self.ended = kind == Kind::Iqk;
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.access()?;
        self.record(&[56, 0, 0x11223344]);
        Ok(0x11223344)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), Error> {
        self.access()?;
        self.record(&[60, 0, saved]);
        self.resumed = true;
        Ok(())
    }
}
fn ready<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn flatten(results: &Results) -> Vec<u32> {
    let mut out = Vec::new();
    for p in &results.paths {
        out.extend_from_slice(&[
            u32::from(p.coarse_failed),
            u32::from(p.fine_failed),
            u32::from(p.tx_failed),
            u32::from(p.rx_failed),
            p.idac,
            p.vbuf,
            p.tx_cfir,
            p.rx_cfir,
            p.enable,
            p.tx_iqc,
            p.rx_iqc,
        ]);
    }
    out.extend_from_slice(&[
        u32::from(results.runs),
        u32::from(results.failures),
        u32::from(results.synth_1_to_2),
    ]);
    out
}
fn smoke_rtw8852b_full_iqk_two_paths_matches_original_linux_dynamic_results() -> TestResult {
    for &(seed, scenario, count, hash, measurements) in CASES {
        let mut model = Model::new(seed, scenario);
        let mut iqk = Iqk::default();
        // SAFETY: isolated fixed B initial PHY0/channel1/20/RF-AB model; every
        // access asserts current admission, and it cannot access physical RF.
        let result = ready(unsafe { iqk.prepare(&mut model) }).unwrap();
        if result
            != if matches!(scenario, 0 | 1 | 8) {
                Ok(())
            } else {
                Err(Error::Terminal)
            }
            || model.count != count
            || model.hash != hash
            || flatten(iqk.diagnostics()) != measurements
            || !model.resumed
            || !model.ended
        {
            return TestResult::Fail(
                "full B IQK dynamic LO/TX/RX/restore sequence differs from original C",
            );
        }
        let expected_attempts = if matches!(scenario, 1 | 2) { 3 } else { 1 };
        if iqk
            .diagnostics()
            .paths
            .iter()
            .any(|p| p.attempts != expected_attempts)
            || iqk.results().is_some() != matches!(scenario, 0 | 1 | 8)
        {
            return TestResult::Fail(
                "failed IQK outcome fabricated calibrated results or LO retry differs",
            );
        }
        let before = model.operations;
        // SAFETY: same isolated model; this is a forbidden replay attempt.
        if ready(unsafe { iqk.prepare(&mut model) }) != Some(Err(Error::Terminal))
            || before != model.operations
        {
            return TestResult::Fail("completed/failed IQK owner replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/radio",
    smoke_rtw8852b_full_iqk_two_paths_matches_original_linux_dynamic_results
);

fn smoke_rtw8852b_iqk_poll_failure_current_admission_and_cancel_are_terminal() -> TestResult {
    for (stuck, rx_stuck, ignore) in [
        (true, false, None),
        (false, true, None),
        (false, false, Some(R_NCTL_CFG)),
        (false, false, Some(R_NCTL_N1)),
        (false, false, Some(0x20fc)),
    ] {
        let mut model = Model::new(0, 0);
        model.stuck = stuck;
        model.rx_stuck = rx_stuck;
        model.ignore = ignore;
        let mut iqk = Iqk::default();
        // SAFETY: isolated fixed initial PHY model, no actual transmitter.
        if ready(unsafe { iqk.prepare(&mut model) }).unwrap().is_ok()
            || iqk.state() != State::Failed
            || iqk.results().is_some()
            || model.resumed
            || model.ended
            || model.now > 10_000
        {
            return TestResult::Fail(
                "stuck RX/NCTL or ignored setup/trigger fabricated IQK readiness",
            );
        }
    }
    let mut baseline = Model::new(0, 0);
    let mut iqk = Iqk::default();
    // SAFETY: isolated baseline records actual access/delay frontiers.
    ready(unsafe { iqk.prepare(&mut baseline) })
        .unwrap()
        .unwrap();
    for frontier in (0..baseline.admissions)
        .step_by(31)
        .chain(core::iter::once(baseline.admissions - 1))
    {
        let mut model = Model::new(0, 0);
        model.deny = Some(frontier);
        let mut iqk = Iqk::default();
        // SAFETY: isolated model denies current authority at this frontier.
        if ready(unsafe { iqk.prepare(&mut model) }) != Some(Err(Error::Policy))
            || iqk.state() != State::Failed
            || iqk.results().is_some()
        {
            return TestResult::Fail("IQK ignored a current authority restriction mid transition");
        }
    }
    for frontier in [0, 3, 20, baseline.delays - 1] {
        let mut model = Model::new(0, 0);
        model.pending = Some(frontier);
        let mut iqk = Iqk::default();
        {
            // SAFETY: isolated model suspends a real IQK delay frontier.
            let mut future = pin!(unsafe { iqk.prepare(&mut model) });
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail(
                    "IQK cancellation fixture missed an awaited native transition",
                );
            }
        }
        let before = model.operations;
        // SAFETY: same isolated model; failed one-shot replay must be inert.
        let replay = ready(unsafe { iqk.prepare(&mut model) });
        if iqk.state() != State::Failed
            || iqk.results().is_some()
            || replay != Some(Err(Error::Terminal))
            || before != model.operations
        {
            return TestResult::Fail("cancelled IQK owner published results or replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/radio",
    smoke_rtw8852b_iqk_poll_failure_current_admission_and_cancel_are_terminal
);
