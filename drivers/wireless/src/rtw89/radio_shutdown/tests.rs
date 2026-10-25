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
    bytes: Vec<u8>,
    xtal: [u8; 256],
    command: u32,
    left: u8,
    busy: u8,
    hash: u64,
    count: u32,
    operations: usize,
    fail: Option<usize>,
    now: u64,
    delays: usize,
    pending: Option<usize>,
    stuck: bool,
    wrong: bool,
    ignore: bool,
}
impl Model {
    fn new(seed: u8, busy: u8) -> Self {
        Self {
            bytes: vec![seed; 0x20000],
            xtal: [seed; 256],
            command: 0,
            left: 0,
            busy,
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            now: 0,
            delays: 0,
            pending: None,
            stuck: false,
            wrong: false,
            ignore: false,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn record(&mut self, words: &[u32]) {
        self.count += 1;
        for word in words {
            for byte in word.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        self.access()?;
        Ok(self.bytes[a as usize])
    }
    fn read16(&mut self, _: u32) -> Result<u16, Error> {
        Err(Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.access()?;
        if a != 0x270 {
            return Ok(u32::from_le_bytes(
                self.bytes[a as usize..a as usize + 4].try_into().unwrap(),
            ));
        }
        if self.command & (1 << 31) != 0 {
            if self.stuck {
                return Ok(self.command);
            }
            if self.left != 0 {
                self.left -= 1;
                return Ok(self.command);
            }
            let address = self.command as u8;
            self.command &= !(1 << 31);
            if self.command & (1 << 24) != 0 {
                self.command =
                    (self.command & !0xff00) | (u32::from(self.xtal[address as usize]) << 8);
            } else if !self.ignore {
                self.xtal[address as usize] = (self.command >> 8) as u8;
            }
            if self.wrong {
                self.command ^= 1;
            }
        }
        Ok(self.command)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.access()?;
        self.bytes[a as usize] = v;
        self.record(&[1, a, u32::from(v)]);
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), Error> {
        Err(Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        self.record(&[4, a, v]);
        self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        if a == 0x270 {
            self.command = v;
            self.left = self.busy;
        }
        Ok(())
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
        self.record(&[8, u as u32, 0]);
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_b_xtal_shutdown_matches_frozen_references_and_real_disable_readback() -> TestResult {
    for &(seed, busy, count, hash) in CASES {
        let mut io = Model::new(seed, busy);
        let mut owner = Shutdown::default();
        // SAFETY: owned inert B XTAL/RF model, no hardware or competing producer.
        let result = ready(unsafe { owner.finish(&mut io, false) });
        if result != Some(Ok(()))
            || owner.state() != State::ShutdownAcknowledged
            || io.count != count
            || io.hash != hash
            || io.xtal[128] & 7 != 0
            || io.xtal[129] & 7 != 0
        {
            return TestResult::Fail(
                "complete B clock/XTAL shutdown differs from the frozen reference",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_xtal_shutdown_matches_frozen_references_and_real_disable_readback
);
fn smoke_rtw89_b_xtal_shutdown_error_cancel_busy_and_echo_never_grant_reset() -> TestResult {
    let mut baseline = Model::new(0xa5, 1);
    let mut owner = Shutdown::default();
    // SAFETY: inert complete XTAL baseline only.
    if ready(unsafe { owner.finish(&mut baseline, false) }) != Some(Ok(())) {
        return TestResult::Fail("shutdown baseline");
    }
    for fail in 0..baseline.operations {
        let mut io = Model::new(0xa5, 1);
        io.fail = Some(fail);
        let mut owner = Shutdown::default();
        // SAFETY: failed actual bus operation must retain Stopping.
        if !matches!(ready(unsafe { owner.finish(&mut io, false) }), Some(Err(_)))
            || owner.state() != State::Stopping
        {
            return TestResult::Fail("partial shutdown acknowledged");
        }
        let n = io.operations;
        // SAFETY: a failed shutdown receipt is not replayable or a reset grant.
        if ready(unsafe { owner.finish(&mut io, false) }) != Some(Err(Error::Terminal))
            || io.operations != n
        {
            return TestResult::Fail("failed XTAL owner replayed");
        }
    }
    for pending in 0..baseline.delays {
        let mut io = Model::new(0xa5, 1);
        io.pending = Some(pending);
        let mut owner = Shutdown::default();
        // SAFETY: cancellation at each real XTAL wait leaves retained Stopping.
        if ready(unsafe { owner.finish(&mut io, false) }).is_some()
            || owner.state() != State::Stopping
        {
            return TestResult::Fail("cancelled shutdown became acknowledged");
        }
    }
    for variant in 0..3 {
        let mut io = Model::new(0xa5, 0);
        let mut owner = Shutdown::default();
        match variant {
            0 => io.stuck = true,
            1 => io.wrong = true,
            _ => io.ignore = true,
        }
        // SAFETY: missing readiness, wrong command echo or an ignored RF write is
        // not a completed actual disable and cannot authorize reset/reclamation.
        if !matches!(ready(unsafe { owner.finish(&mut io, false) }), Some(Err(_)))
            || owner.state() != State::Stopping
        {
            return TestResult::Fail("busy/forged/ignored RF shutdown accepted");
        }
        if variant == 0 && io.now > 200_000 {
            return TestResult::Fail("shutdown controller wait unbounded");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_xtal_shutdown_error_cancel_busy_and_echo_never_grant_reset
);
