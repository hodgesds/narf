use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    hash: u64,
    count: u32,
    now: u64,
    operations: usize,
    admissions: usize,
    fail: Option<usize>,
    deny: Option<usize>,
    pending: Option<usize>,
    delays: usize,
    second: bool,
    stuck: Option<u32>,
}
impl Model {
    fn new(seed: u8, high: bool, second: bool) -> Self {
        let word = u32::from(seed) * 0x01010101;
        let mut words = vec![word; 0x20000 / 4];
        words[(0x10000 + R_DPD_BF) as usize / 4] = if high {
            ((31 << B_DPD_BF_OFDM.trailing_zeros()) & B_DPD_BF_OFDM)
                | ((20 << B_DPD_BF_SCA.trailing_zeros()) & B_DPD_BF_SCA)
        } else {
            0
        };
        Self {
            words,
            rf: core::array::from_fn(|_| vec![word & 0xfffff; 0x10100]),
            hash: 14695981039346656037,
            count: 0,
            now: 0,
            operations: 0,
            admissions: 0,
            fail: None,
            deny: None,
            pending: None,
            delays: 0,
            second,
            stuck: None,
        }
    }
    fn value(&mut self, v: u32) {
        for b in v.to_le_bytes() {
            self.hash ^= u64::from(b);
            self.hash = self.hash.wrapping_mul(1099511628211);
        }
    }
    fn record(&mut self, values: &[u32]) {
        self.count += 1;
        for v in values {
            self.value(*v);
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        let op = self.operations;
        self.operations += 1;
        if self.fail == Some(op) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn selector(&self, address: u32, mask: u32) -> u32 {
        (self.words[(0x10000 + address) as usize / 4] & mask) >> mask.trailing_zeros()
    }
    fn read(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        let r = a - 0x10000;
        let mut v = self.words[a as usize / 4];
        if r == R_DRCK_RS {
            v = 0x98008;
        }
        if r == R_ADDCKR0 {
            v = 0xabcdf;
        }
        if r == R_ADDCKR1 {
            v = 0x54321;
        }
        if [R_DACK_S0P0, R_DACK_S0P1, R_DACK_S1P1].contains(&r) {
            v |= 1 << 31;
        }
        if r == R_DACK_S1P0 {
            v = (v & !(1 << 31)) | if self.second { 0 } else { 1 << 31 };
        }
        if r == R_DACK_S0P2 {
            v = ((0x40 + self.selector(R_DCOF0, B_DCOF0_V)) << 24) | 0x123404;
        }
        if r == R_DACK_S0P3 {
            v = ((0x60 + self.selector(R_DCOF8, B_DCOF8_V)) << 24) | 0x123404;
        }
        if r == R_DACK10S {
            v = ((0x80 + self.selector(R_DACK10, B_DACK10)) << 24) | 0x123404;
        }
        if r == R_DACK11S {
            v = ((0xa0 + self.selector(R_DACK11, B_DACK11)) << 24) | 0x123404;
        }
        if self.stuck == Some(r) {
            v = 0;
        }
        self.record(&[0, a, v]);
        Ok(v)
    }
}
impl Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.read(a)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        self.words[a as usize / 4] = v;
        self.record(&[4, a, v]);
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        let d = self.delays;
        self.delays += 1;
        self.record(&[8, us as u32, 0]);
        if self.pending == Some(d) {
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
            Err(Error::Policy)
        } else {
            Ok(())
        }
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        self.access()?;
        let mut value = self.rf[path as usize][address as usize];
        if address == RR_RCKS {
            value |= 8;
        }
        if address == RR_RCKC && value == 0x240 {
            value |= 0x4800;
        }
        if self.stuck == Some(0x100000 + address) {
            value = 0;
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
        let old = self.rf[path as usize][address as usize];
        self.rf[path as usize][address as usize] =
            (old & !mask) | ((value << mask.trailing_zeros()) & mask);
        self.record(&[36, u32::from(path), address, mask, value]);
        Ok(())
    }
    async fn begin(&mut self, kind: Kind) -> Result<(), Error> {
        self.access()?;
        self.record(&[48, u32::from(kind == Kind::Rxdck), 0]);
        Ok(())
    }
    async fn end(&mut self, kind: Kind) -> Result<(), Error> {
        self.access()?;
        self.record(&[48, u32::from(kind == Kind::Rxdck), 1]);
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.access()?;
        self.record(&[56, 0, 0x11223344]);
        Ok(0x11223344)
    }
    async fn resume(&mut self, v: u32) -> Result<(), Error> {
        self.access()?;
        self.record(&[60, 0, v]);
        Ok(())
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn flatten(r: &Results) -> Vec<u8> {
    let mut bytes = Vec::new();
    for path in r.msbk {
        for group in path {
            bytes.extend_from_slice(&group);
        }
    }
    for path in r.dadck {
        bytes.extend_from_slice(&path);
    }
    for values in [r.addck, r.bias] {
        for path in values {
            for v in path {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    bytes.push(r.dpd_gain);
    bytes
}
fn smoke_rtw89_b_initial_rck_dack_rxdck_match_original_linux_c() -> TestResult {
    for &(seed, high, second, count, hash, measurements) in CASES {
        let mut io = Model::new(seed, high, second);
        let mut rfk = Rfk::default();
        // SAFETY: complete exclusive inert B register/RF/coexistence model,
        // explicit measured-input fixture and no real DMA/radio producer.
        if ready(unsafe { rfk.prepare(&mut io) }) != Some(Ok(()))
            || rfk.state() != State::BasicCalibrated
            || io.count != count
            || io.hash != hash
            || rfk.results().is_none_or(|r| flatten(r) != measurements)
        {
            return TestResult::Fail(
                "B RCK/DACK/RXDCK read/write/measurement stream differs from original C",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_initial_rck_dack_rxdck_match_original_linux_c
);
fn smoke_rtw89_b_basic_rfk_error_cancel_and_policy_never_publish_results() -> TestResult {
    let mut baseline = Model::new(0, false, false);
    let mut rfk = Rfk::default();
    // SAFETY: same complete owned inert profile used solely as a model.
    if ready(unsafe { rfk.prepare(&mut baseline) }) != Some(Ok(())) {
        return TestResult::Fail("RFK negative baseline");
    }
    let failures = [
        0,
        1,
        10,
        baseline.operations / 4,
        baseline.operations / 2,
        baseline.operations * 3 / 4,
        baseline.operations - 1,
    ];
    for failed in failures {
        let mut io = Model::new(0, false, false);
        io.fail = Some(failed);
        let mut rfk = Rfk::default();
        // SAFETY: injected private bus error must leave retained calibration.
        if ready(unsafe { rfk.prepare(&mut io) })
            != Some(Err(Error::Register(power::Error::Access)))
            || rfk.state() != State::Calibrating
            || rfk.results().is_some()
        {
            return TestResult::Fail("RFK error published calibration");
        }
        let before = io.operations;
        // SAFETY: terminal attempt must reject before a new register command.
        if ready(unsafe { rfk.prepare(&mut io) }) != Some(Err(Error::Terminal))
            || io.operations != before
        {
            return TestResult::Fail("failed RFK owner replayed hardware");
        }
    }
    for pending in 0..baseline.delays {
        let mut io = Model::new(0, false, false);
        io.pending = Some(pending);
        let mut rfk = Rfk::default();
        // SAFETY: cancellation in this inert fixture must retain Calibrating.
        if ready(unsafe { rfk.prepare(&mut io) }).is_some()
            || rfk.state() != State::Calibrating
            || rfk.results().is_some()
        {
            return TestResult::Fail("cancelled RFK published a receipt");
        }
        let before = io.operations;
        // SAFETY: dropped attempt stays terminal before any further I/O.
        if ready(unsafe { rfk.prepare(&mut io) }) != Some(Err(Error::Terminal))
            || io.operations != before
        {
            return TestResult::Fail("cancelled RFK restarted");
        }
    }
    for deny in [0, 1, 20, baseline.admissions / 2, baseline.admissions - 1] {
        let mut io = Model::new(0, false, false);
        io.deny = Some(deny);
        let mut rfk = Rfk::default();
        // SAFETY: explicit model permission revocation, never a live board.
        if ready(unsafe { rfk.prepare(&mut io) }) != Some(Err(Error::Policy))
            || rfk.results().is_some()
            || (deny == 0 && io.operations != 0)
        {
            return TestResult::Fail("RFK ignored current board/policy denial");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_basic_rfk_error_cancel_and_policy_never_publish_results
);
fn smoke_rtw89_b_basic_rfk_handshake_deadlines_are_fail_closed() -> TestResult {
    for stuck in [
        0x100000 + RR_RCKS,
        R_DRCK_RS,
        R_ADDCKR0,
        R_ADDCKR1,
        R_DACK_S0P0,
        R_DACK_S0P2,
    ] {
        let mut io = Model::new(0, false, false);
        io.stuck = Some(stuck);
        let mut rfk = Rfk::default();
        // SAFETY: inert model with one actual controller readiness condition
        // withheld, and finite source poll budgets. No native emission exists.
        if ready(unsafe { rfk.prepare(&mut io) })
            != Some(Err(Error::Register(power::Error::Timeout)))
            || rfk.results().is_some()
            || io.now > 50000
        {
            return TestResult::Fail("RFK readiness timeout continued or was unbounded");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_basic_rfk_handshake_deadlines_are_fail_closed
);

fn smoke_rtw89_b_channel_rxdck_uses_same_original_source_and_keeps_partial_owner() -> TestResult {
    for &(seed, count, hash) in RXDCK_CASES {
        let mut io = Model::new(seed, false, false);
        let mut owner = ChannelRxDck::default();
        // SAFETY: private owned exact B RF/BB model, explicit measured boundary.
        if ready(unsafe { owner.prepare(&mut io) }) != Some(Ok(()))
            || owner.state() != State::BasicCalibrated
            || io.count != count
            || io.hash != hash
        {
            return TestResult::Fail("fresh channel RXDCK differs from original C");
        }
        for failed in 0..io.operations {
            let mut io = Model::new(seed, false, false);
            io.fail = Some(failed);
            let mut owner = ChannelRxDck::default();
            // SAFETY: each actual source access failure must keep one partial attempt.
            let result = ready(unsafe { owner.prepare(&mut io) });
            if !matches!(result, Some(Err(_))) || owner.state() != State::Calibrating {
                return TestResult::Fail("partial channel RXDCK completed");
            }
        }
        for pending in 0..2 {
            let mut io = Model::new(seed, false, false);
            io.pending = Some(pending);
            let mut owner = ChannelRxDck::default();
            // SAFETY: dropped actual A/B settling waits must retain partial state.
            if ready(unsafe { owner.prepare(&mut io) }).is_some()
                || owner.state() != State::Calibrating
            {
                return TestResult::Fail("cancelled channel RXDCK completed");
            }
            let n = io.operations;
            // SAFETY: partial one-shot owner must refuse a fresh channel attempt.
            if ready(unsafe { owner.prepare(&mut io) }) != Some(Err(Error::Terminal))
                || io.operations != n
            {
                return TestResult::Fail("cancelled channel RXDCK replayed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_channel_rxdck_uses_same_original_source_and_keeps_partial_owner
);
