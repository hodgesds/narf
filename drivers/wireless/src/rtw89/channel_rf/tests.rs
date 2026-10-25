use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    rf: [[u32; 512]; 2],
    lock_after: u8,
    lock_reads: u8,
    busy: u16,
    busy_left: u16,
    hash: u64,
    count: u32,
    operations: usize,
    fail: Option<usize>,
    delays: usize,
    pending: Option<usize>,
    now: u64,
    denied: bool,
    ignore: bool,
}
impl Model {
    fn new(seed: u8, lock: u8, busy: u16) -> Self {
        Self {
            rf: [[(u32::from(seed) * 0x010101) & RFREG_MASK; 512]; 2],
            lock_after: lock,
            lock_reads: 0,
            busy,
            busy_left: 0,
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            delays: 0,
            pending: None,
            now: 0,
            denied: false,
            ignore: false,
        }
    }
    fn slot(a: u32) -> usize {
        ((a & 255) | if a & 0x10000 != 0 { 256 } else { 0 }) as usize
    }
    fn access(&mut self) -> Result<(), rfk::Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(rfk::Error::Register(power::Error::Access))
        } else {
            Ok(())
        }
    }
    fn record(&mut self, words: &[u32]) {
        self.count += 1;
        for w in words {
            for b in w.to_le_bytes() {
                self.hash ^= u64::from(b);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
    }
}
impl power::Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, _: u32) -> Result<u32, power::Error> {
        Err(power::Error::Access)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, u: u64) {
        let n = self.delays;
        self.delays += 1;
        if self.pending == Some(n) {
            core::future::pending::<()>().await;
        }
        self.now += u;
        self.record(&[8, u as u32]);
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        if self.denied {
            Err(rfk::Error::Policy)
        } else {
            Ok(())
        }
    }
    async fn rf_read(&mut self, p: u8, a: u32, m: u32) -> Result<u32, rfk::Error> {
        self.access()?;
        let mut v = self.rf[p as usize][Self::slot(a)];
        if a == RR_SYNFB && m == RR_SYNFB_LK {
            self.lock_reads += 1;
            v = (v & !m)
                | if self.lock_reads > self.lock_after {
                    m
                } else {
                    0
                };
        }
        if a == RR_LPF && m == RR_LPF_BUSY {
            v = (v & !m) | if self.busy_left != 0 { m } else { 0 };
            self.busy_left = self.busy_left.saturating_sub(1);
        }
        v = (v & m) >> m.trailing_zeros();
        self.record(&[32, u32::from(p), a, m, v]);
        Ok(v)
    }
    async fn rf_write(&mut self, p: u8, a: u32, m: u32, v: u32) -> Result<(), rfk::Error> {
        self.access()?;
        if !self.ignore {
            let old = &mut self.rf[p as usize][Self::slot(a)];
            *old = (*old & !m) | ((v << m.trailing_zeros()) & m);
        }
        if p == 0 && a == RR_CFGCH {
            self.busy_left = self.busy;
        }
        self.record(&[16, u32::from(p), a, m, v]);
        Ok(())
    }
    async fn begin(&mut self, _: rfk::Kind) -> Result<(), rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn end(&mut self, _: rfk::Kind) -> Result<(), rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn pause(&mut self) -> Result<u32, rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn resume(&mut self, _: u32) -> Result<(), rfk::Error> {
        Err(rfk::Error::Policy)
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_b_channel1_rf_synth_matches_frozen_references() -> TestResult {
    for &(seed, lock, busy, count, hash) in CASES {
        let mut io = Model::new(seed, lock, u16::from(busy));
        let mut owner = Channel::default();
        // SAFETY: explicit inert qualification and owned RF words; no native caller.
        let result = ready(unsafe { owner.prepare(&mut io) });
        if result != Some(Ok(()))
            || owner.state() != State::SynthConfigured
            || io.count != count
            || io.hash != hash
        {
            return TestResult::Fail("B channel1 RF synth/LCK differs from the frozen reference");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_channel1_rf_synth_matches_frozen_references
);
fn smoke_rtw89_b_rf_synth_fail_cancel_and_lock_deadline_are_terminal() -> TestResult {
    let mut baseline = Model::new(0x5a, 3, 2);
    let mut owner = Channel::default();
    // SAFETY: baseline complete owned inert RF model only.
    if ready(unsafe { owner.prepare(&mut baseline) }) != Some(Ok(())) {
        return TestResult::Fail("RF synth baseline");
    }
    for failed in 0..baseline.operations {
        let mut io = Model::new(0x5a, 3, 2);
        io.fail = Some(failed);
        let mut owner = Channel::default();
        // SAFETY: injected current bus error must retain one failed attempt.
        if !matches!(ready(unsafe { owner.prepare(&mut io) }), Some(Err(_)))
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("partial RF channel was published");
        }
        let n = io.operations;
        // SAFETY: failed owner must reject before a new synth transaction.
        if ready(unsafe { owner.prepare(&mut io) }) != Some(Err(Error::Terminal))
            || io.operations != n
        {
            return TestResult::Fail("RF synth failure replayed");
        }
    }
    for pending in 0..baseline.delays {
        let mut io = Model::new(0x5a, 3, 2);
        io.pending = Some(pending);
        let mut owner = Channel::default();
        // SAFETY: dropping each actual wait must not create synth readiness.
        if ready(unsafe { owner.prepare(&mut io) }).is_some() || owner.state() != State::Preparing {
            return TestResult::Fail("cancelled synth owner ready");
        }
    }
    for variant in 0..4 {
        let mut io = Model::new(0, 0, 0);
        let mut owner = Channel::default();
        match variant {
            0 => io.lock_after = 255,
            1 => io.busy = 2000,
            2 => io.ignore = true,
            _ => io.denied = true,
        }
        // SAFETY: failed actual lock/LPF/readback or admission cannot qualify channel.
        if !matches!(ready(unsafe { owner.prepare(&mut io) }), Some(Err(_)))
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("unlocked/ignored/denied synth returned readiness");
        }
        if variant == 1 && io.now != 1000 {
            return TestResult::Fail("RF LPF deadline not bounded to source budget");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_rf_synth_fail_cancel_and_lock_deadline_are_terminal
);
