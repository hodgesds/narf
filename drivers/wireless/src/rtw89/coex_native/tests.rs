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
    lte: [u32; 64],
    hash: u64,
    count: u32,
    operations: usize,
    fail: Option<usize>,
    pending: Option<usize>,
    delays: usize,
    now: u64,
    denied: bool,
    stuck: bool,
    ignore: Option<u32>,
}
impl Model {
    fn new(seed: u8) -> Self {
        Self {
            bytes: vec![seed; 0x20000],
            lte: [u32::from(seed) * 0x01010101; 64],
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            pending: None,
            delays: 0,
            now: 0,
            denied: false,
            stuck: false,
            ignore: None,
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
    fn octet(&mut self, v: u8) {
        self.hash ^= u64::from(v);
        self.hash = self.hash.wrapping_mul(1099511628211);
    }
    fn values(&mut self, values: &[u32]) {
        self.count += 1;
        for v in values {
            for b in v.to_le_bytes() {
                self.octet(b);
            }
        }
    }
    fn write(&mut self, a: u32, b: &[u8]) -> Result<(), power::Error> {
        self.access()?;
        if self.ignore != Some(a) {
            self.bytes[a as usize..a as usize + b.len()].copy_from_slice(b);
        }
        let mut v = [0; 4];
        v[..b.len()].copy_from_slice(b);
        self.values(&[b.len() as u32, a, u32::from_le_bytes(v)]);
        Ok(())
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(self.bytes[a as usize] | if a == 0xdaf3 && !self.stuck { 32 } else { 0 })
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.access()?;
        Ok(u16::from_le_bytes(
            self.bytes[a as usize..a as usize + 2].try_into().unwrap(),
        ))
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        Ok(u32::from_le_bytes(
            self.bytes[a as usize..a as usize + 4].try_into().unwrap(),
        ))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.write(a, &[v])
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.write(a, &v.to_le_bytes())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.write(a, &v.to_le_bytes())?;
        if a == 0xdaf0 && self.ignore != Some(a) {
            let i = (v & 255) as usize / 4;
            if v & 0x40000000 != 0 {
                self.lte[i] = u32::from_le_bytes(self.bytes[0xdaf4..0xdaf8].try_into().unwrap());
            } else {
                self.bytes[0xdaf8..0xdafc].copy_from_slice(&self.lte[i].to_le_bytes());
            }
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
        self.values(&[8, u as u32, 0]);
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
    async fn rf_write(&mut self, p: u8, a: u32, m: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        self.values(&[16, u32::from(p), a, m, v]);
        Ok(())
    }
    async fn command(&mut self, f: u8, b: &[u8], done: bool) -> Result<(), Error> {
        self.access()?;
        self.values(&[32, u32::from(f), u32::from(done), b.len() as u32]);
        for byte in b {
            self.octet(*byte);
        }
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
fn smoke_rtw89_b_wlan_only_pta_matches_frozen_references() -> TestResult {
    for &(seed, rfe, count, hash) in CASES {
        let mut io = Model::new(seed);
        let mut owner = Coex::default();
        // SAFETY: inert owned bytes and explicit model qualification, with no RF/DMA.
        let result = ready(unsafe { owner.prepare(&mut io, rfe, 1, Protocol) });
        if result != Some(Ok(()))
            || owner.state() != State::WlanOnly
            || io.count != count
            || io.hash != hash
        {
            return TestResult::Fail(
                "B PTA/grant/TRX/firmware policy differs from the frozen reference",
            );
        }
    }
    for v in [[0, 29, 28, 255], [0, 29, 122, 0], [1, 0, 0, 0]] {
        if Protocol::for_version(v).is_some() {
            return TestResult::Fail("unsupported firmware coex ABI guessed");
        }
    }
    if Protocol::for_version([0, 29, 29, 18]).is_none() {
        return TestResult::Fail("real installed B protocol rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_wlan_only_pta_matches_frozen_references
);
fn smoke_rtw89_b_wlan_only_fault_cancel_and_ignored_grant_never_replay() -> TestResult {
    let mut baseline = Model::new(0);
    let mut owner = Coex::default();
    // SAFETY: same inert private byte/register model.
    if ready(unsafe { owner.prepare(&mut baseline, 1, 1, Protocol) }) != Some(Ok(())) {
        return TestResult::Fail("coex baseline");
    }
    for fail in 0..baseline.operations {
        let mut io = Model::new(0);
        io.fail = Some(fail);
        let mut owner = Coex::default();
        // SAFETY: injected actual access failure must retain Preparing.
        if ready(unsafe { owner.prepare(&mut io, 1, 1, Protocol) }).is_none()
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("coex failure published readiness");
        }
        let n = io.operations;
        // SAFETY: retained failed owner must refuse before another access.
        if ready(unsafe { owner.prepare(&mut io, 1, 1, Protocol) }) != Some(Err(Error::Terminal))
            || io.operations != n
        {
            return TestResult::Fail("coex failure replayed");
        }
    }
    for pending in 0..baseline.delays {
        let mut io = Model::new(0);
        io.pending = Some(pending);
        let mut owner = Coex::default();
        // SAFETY: drop at the real source wait leaves Preparing.
        if ready(unsafe { owner.prepare(&mut io, 1, 1, Protocol) }).is_some()
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("coex cancellation ready");
        }
    }
    for address in [0xdaf0, 0x73, 0xc67c] {
        let mut io = Model::new(0);
        io.ignore = Some(address);
        let mut owner = Coex::default();
        // SAFETY: ignored critical ownership programming cannot qualify RFK.
        if ready(unsafe { owner.prepare(&mut io, 1, 1, Protocol) })
            != Some(Err(Error::Register(power::Error::Access)))
        {
            return TestResult::Fail("ignored coex ownership accepted");
        }
    }
    let mut io = Model::new(0);
    io.denied = true;
    let mut owner = Coex::default();
    // SAFETY: denied model policy must reject before actual register publication.
    if ready(unsafe { owner.prepare(&mut io, 1, 1, Protocol) }) != Some(Err(Error::Policy))
        || io.operations != 0
    {
        return TestResult::Fail("coex policy denial reached hardware");
    }
    let mut io = Model::new(0);
    io.stuck = true;
    let mut owner = Coex::default();
    // SAFETY: private LTE model never becomes ready and must time out boundedly.
    if ready(unsafe { owner.prepare(&mut io, 1, 1, Protocol) })
        != Some(Err(Error::Register(power::Error::Timeout)))
        || io.now != 50_000
    {
        return TestResult::Fail("LTE grant wait unbounded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_wlan_only_fault_cancel_and_ignored_grant_never_replay
);
