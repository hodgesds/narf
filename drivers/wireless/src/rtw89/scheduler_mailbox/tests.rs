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
    now: u64,
    pending: bool,
    denied: bool,
    hold: bool,
    wrong: bool,
    ignore: bool,
}
impl Model {
    fn new(seed: u8) -> Self {
        let mut bytes = vec![seed; 65536];
        bytes[0x8160] = 0;
        bytes[0x8164] = 0;
        Self {
            bytes,
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            now: 0,
            pending: false,
            denied: false,
            hold: false,
            wrong: false,
            ignore: false,
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
    fn write(&mut self, a: u32, b: &[u8]) -> Result<(), power::Error> {
        self.access()?;
        self.bytes[a as usize..a as usize + b.len()].copy_from_slice(b);
        self.count += 1;
        let mut v = [0; 4];
        v[..b.len()].copy_from_slice(b);
        for v in [b.len() as u32, a, u32::from_le_bytes(v)] {
            for byte in v.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
        Ok(())
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(self.bytes[a as usize])
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
        self.write(a, &[v])?;
        if a == 0x8160 && v == 1 && !self.hold {
            self.bytes[a as usize] = 0;
            self.bytes[0x8164] = 1;
            self.bytes[0x8150..0x8154]
                .copy_from_slice(&(if self.wrong { 0x203u32 } else { 0x204 }).to_le_bytes());
            if !self.ignore {
                let enable = self.bytes[0x8142..0x8144].to_vec();
                self.bytes[0xc348..0xc34a].copy_from_slice(&enable);
            }
        }
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.write(a, &v.to_le_bytes())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.write(a, &v.to_le_bytes())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, u: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += u;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), power::Error> {
        if self.denied {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_b_firmware_scheduler_mailbox_matches_original_linux_c() -> TestResult {
    for &(seed, enable, count, hash) in CASES {
        let mut io = Model::new(seed);
        let mut owner = Mailbox::default();
        if ready(owner.scheduler(&mut io, enable)) != Some(Ok(()))
            || ready(owner.scheduler(&mut io, enable ^ 0xffff)) != Some(Ok(()))
            || owner.state() != State::Idle
            || io.count != count
            || io.hash != hash
        {
            return TestResult::Fail(
                "actual scheduler register messages/counters differ from original C",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_firmware_scheduler_mailbox_matches_original_linux_c
);
fn smoke_rtw89_b_scheduler_stale_reply_fault_cancel_and_readback_are_terminal() -> TestResult {
    let mut baseline = Model::new(0);
    let mut owner = Mailbox::default();
    if ready(owner.scheduler(&mut baseline, 0)) != Some(Ok(())) {
        return TestResult::Fail("mailbox baseline");
    }
    for fail in 0..baseline.operations {
        let mut io = Model::new(0);
        io.fail = Some(fail);
        let mut owner = Mailbox::default();
        if !matches!(ready(owner.scheduler(&mut io, 0)), Some(Err(_)))
            || owner.state() != State::Pending
        {
            return TestResult::Fail("mailbox failure returned reusable owner");
        }
        let n = io.operations;
        if ready(owner.scheduler(&mut io, 0)) != Some(Err(power::Error::Terminal))
            || io.operations != n
        {
            return TestResult::Fail("failed register command replayed");
        }
    }
    for variant in 0..6 {
        let mut io = Model::new(0);
        let mut owner = Mailbox::default();
        match variant {
            0 => io.bytes[0x8164] = 1,
            1 => io.wrong = true,
            2 => {
                io.ignore = true;
                io.bytes[0xc348] = 1;
            }
            3 => {
                io.pending = true;
                io.hold = true;
            }
            4 => io.denied = true,
            _ => io.hold = true,
        }
        let result = ready(owner.scheduler(&mut io, 0));
        if (variant == 3 && result.is_some())
            || (variant != 3 && !matches!(result, Some(Err(_))))
            || owner.state() != State::Pending
        {
            return TestResult::Fail("stale/pending/denied scheduler operation became reusable");
        }
        if variant == 5 && io.now != 1_000_000 {
            return TestResult::Fail("mailbox completion deadline differs");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_scheduler_stale_reply_fault_cancel_and_readback_are_terminal
);
