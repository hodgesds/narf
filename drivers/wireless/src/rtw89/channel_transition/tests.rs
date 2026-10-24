use super::super::power::Io;
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
    hash: u64,
    count: u32,
    operations: usize,
    fail: Option<usize>,
    denied: bool,
    ignore: bool,
    gone: bool,
    pending: bool,
    now: u64,
}
impl Model {
    fn new(seed: u8, _rx: u8) -> Self {
        Self {
            bytes: vec![seed; 0x20000],
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            denied: false,
            ignore: false,
            gone: false,
            pending: false,
            now: 0,
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn record(&mut self, words: [u32; 3]) {
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
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(self.bytes[a as usize])
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        if self.gone {
            return Ok(u32::MAX);
        }
        Ok(u32::from_le_bytes(
            self.bytes[a as usize..a as usize + 4].try_into().unwrap(),
        ))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access()?;
        if !self.ignore {
            self.bytes[a as usize] = v;
        }
        self.record([1, a, u32::from(v)]);
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        if !self.ignore {
            self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        }
        self.record([4, a, v]);
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, u: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += u;
        self.record([8, u as u32, 0]);
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        if self.denied {
            Err(Error::Policy)
        } else {
            Ok(())
        }
    }
    async fn rf_read(&mut self, _: u8, _: u32, _: u32) -> Result<u32, Error> {
        Err(Error::Table)
    }
    async fn rf_write(&mut self, _: u8, _: u32, _: u32, _: u32) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn begin(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn end(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.access()?;
        let saved = u32::from_le_bytes(self.bytes[0xc348..0xc34c].try_into().unwrap()) & 65535;
        self.record([32, 0, saved]);
        Ok(saved)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), Error> {
        self.access()?;
        self.record([64, 0, saved]);
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
fn complete(owner: &mut Transition, io: &mut Model) -> Option<Result<(), Error>> {
    // SAFETY: caller supplies owned inert exact B bracket state and word model.
    ready(unsafe {
        async {
            owner.enter(io).await?;
            owner.finish(io).await
        }
    })
}
fn smoke_rtw89_b_channel_bracket_matches_original_linux_c() -> TestResult {
    for &(seed, count, hash) in CASES {
        let mut io = Model::new(seed, 0);
        let mut owner = Transition::default();
        if complete(&mut owner, &mut io) != Some(Ok(()))
            || owner.state() != State::Finished
            || io.count != count
            || io.hash != hash
            || io.now != 41
        {
            return TestResult::Fail("B channel helper differs from original C");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_channel_bracket_matches_original_linux_c
);
fn smoke_rtw89_b_channel_bracket_errors_cancel_and_reset_readback_are_terminal() -> TestResult {
    let mut baseline = Model::new(0xa5, 0);
    let mut owner = Transition::default();
    if complete(&mut owner, &mut baseline) != Some(Ok(())) {
        return TestResult::Fail("channel bracket baseline");
    }
    for fail in 0..baseline.operations {
        let mut io = Model::new(0xa5, 0);
        io.fail = Some(fail);
        let mut owner = Transition::default();
        if !matches!(complete(&mut owner, &mut io), Some(Err(_)))
            || matches!(owner.state(), State::New | State::Finished)
        {
            return TestResult::Fail("partial bracket completed");
        }
        let n = io.operations;
        // SAFETY: a partial bracket must refuse re-entry without more transitions.
        if ready(unsafe { owner.enter(&mut io) }) != Some(Err(Error::Terminal))
            || io.operations != n
        {
            return TestResult::Fail("partial bracket replayed");
        }
    }
    for variant in 0..4 {
        let mut io = Model::new(0xa5, 0);
        let mut owner = Transition::default();
        match variant {
            0 => io.pending = true,
            1 => io.ignore = true,
            2 => io.denied = true,
            _ => io.gone = true,
        };
        let r = complete(&mut owner, &mut io);
        if (variant == 0 && r.is_some())
            || (variant != 0 && !matches!(r, Some(Err(_))))
            || owner.state() == State::Finished
        {
            return TestResult::Fail("cancel/ignored/policy bracket completed");
        }
    }
    let mut io = Model::new(0, 0);
    let mut owner = Transition::default();
    // SAFETY: no entry occurred, so finish must reject before any register access.
    if ready(unsafe { owner.finish(&mut io) }) != Some(Err(Error::Terminal)) || io.operations != 0 {
        return TestResult::Fail("unearned channel release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_channel_bracket_errors_cancel_and_reset_readback_are_terminal
);
