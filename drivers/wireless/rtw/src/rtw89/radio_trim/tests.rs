use super::super::power::{self, Io};
use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    rf: [[u32; 256]; 2],
    hash: u64,
    count: u32,
    operations: usize,
    fail: Option<usize>,
    pending: bool,
    denied: bool,
    ignore: bool,
}
impl Model {
    fn new() -> Self {
        Self {
            rf: [[0; 256]; 2],
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            pending: false,
            denied: false,
            ignore: false,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(power::Error::Access.into())
        } else {
            Ok(())
        }
    }
}
impl Io for Model {
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
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Access)
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
    async fn rf_read(&mut self, p: u8, a: u32, m: u32) -> Result<u32, Error> {
        self.access()?;
        Ok((self.rf[p as usize][a as usize] & m) >> m.trailing_zeros())
    }
    async fn rf_write(&mut self, p: u8, a: u32, m: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        if self.pending {
            core::future::pending::<()>().await;
        }
        if !self.ignore {
            let r = &mut self.rf[p as usize][a as usize];
            *r = (*r & !m) | ((v << m.trailing_zeros()) & m);
        }
        self.count += 1;
        for w in [u32::from(p), a, m, v] {
            for b in w.to_le_bytes() {
                self.hash ^= u64::from(b);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
        Ok(())
    }
    async fn begin(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn end(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        Err(Error::Table)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Table)
    }
}
fn inputs(flags: u8) -> Calibration {
    Calibration {
        thermal: [0; 2],
        tssi_cck: [[0; 6]; 2],
        tssi_mcs: [[0; 19]; 2],
        tssi_trim: [[0; 8]; 2],
        trim_programmed: false,
        thermal_trim: [0x5d, 0x12],
        thermal_programmed: flags & 1 != 0,
        pa_bias: [0xa3, 0x7e],
        pa_programmed: flags & 2 != 0,
        gain_offset: [[0; 5]; 2],
        offset_valid: false,
        gain_comp: [[0; 5]; 2],
        comp_valid: false,
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_b_real_physical_trim_matches_frozen_references_and_rejects_partial() -> TestResult {
    for &(flags, count, hash) in CASES {
        let mut io = Model::new();
        let mut owner = Trim::default();
        // SAFETY: inert private exact B factory/RF model, no physical emission.
        if ready(unsafe { owner.prepare(&mut io, &inputs(flags)) }) != Some(Ok(()))
            || owner.state() != State::Applied
            || io.count != count
            || io.hash != hash
        {
            return TestResult::Fail("B physical trims differ from the frozen reference");
        }
    }
    for variant in 0..15 {
        let mut io = Model::new();
        let mut owner = Trim::default();
        match variant {
            0..=11 => io.fail = Some(variant),
            12 => io.pending = true,
            13 => io.denied = true,
            _ => io.ignore = true,
        };
        // SAFETY: each real RF read/write failure or cancellation keeps partial trim.
        let r = ready(unsafe { owner.prepare(&mut io, &inputs(3)) });
        if (variant == 12 && r.is_some())
            || (variant != 12 && !matches!(r, Some(Err(_))))
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("partial physical trim completed");
        }
        let n = io.operations;
        // SAFETY: one-shot partial owner must reject without another RF transaction.
        if ready(unsafe { owner.prepare(&mut io, &inputs(3)) }) != Some(Err(Error::Terminal))
            || io.operations != n
        {
            return TestResult::Fail("physical trim replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_real_physical_trim_matches_frozen_references_and_rejects_partial
);
