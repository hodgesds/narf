//! Completed-read restoration, real timeout retention and all-I/O failures.
use super::{
    ddv::Ddv,
    mac::ChipId,
    power::{Error, Io},
};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    regs: Vec<u8>,
    physical: Vec<u8>,
    writes: Vec<(u8, u32, u32)>,
    delays: Vec<u64>,
    address: usize,
    now: u64,
    operations: usize,
    fail_at: Option<usize>,
    stall: bool,
    pending: bool,
}
impl Model {
    fn new() -> Self {
        let mut physical = vec![0xff; 2048];
        physical[0x5ea..0x5ec].copy_from_slice(&[0x21, 0x43]);
        Self {
            regs: vec![0; 256],
            physical,
            writes: Vec::new(),
            delays: Vec::new(),
            address: 0,
            now: 0,
            operations: 0,
            fail_at: None,
            stall: false,
            pending: false,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let at = self.operations;
        self.operations += 1;
        if self.fail_at == Some(at) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn word(&self, a: u32) -> u32 {
        u32::from_le_bytes(self.regs[a as usize..a as usize + 4].try_into().unwrap())
    }
    fn write(&mut self, width: u8, a: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        self.writes.push((width, a, v));
        let n = usize::from(width / 8);
        self.regs[a as usize..a as usize + n].copy_from_slice(&v.to_le_bytes()[..n]);
        if a == 0x30 {
            self.address = (v as usize >> 16) & 2047;
        }
        Ok(())
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        self.access()?;
        Ok(self.regs[a as usize])
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        self.access()?;
        Ok(u16::from_le_bytes(
            self.regs[a as usize..a as usize + 2].try_into().unwrap(),
        ))
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.access()?;
        if a == 0x30 && !self.stall {
            Ok(self.word(a) | (1 << 29) | u32::from(self.physical[self.address]))
        } else {
            Ok(self.word(a))
        }
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.write(8, a, u32::from(v))
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.write(16, a, u32::from(v))
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.write(32, a, v)
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.delays.push(us);
        self.now += if self.stall && us == 1 { 10_001 } else { us };
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
const PROFILES: &[(ChipId, u8)] = &[
    (ChipId::Rtl8852A, 0),
    (ChipId::Rtl8852B, 0),
    (ChipId::Rtl8852B, 1),
    (ChipId::Rtl8852C, 0),
    (ChipId::Rtl8851B, 0),
];

fn smoke_rtw89_ddv_completed_read_restores_exact_linux_controls() -> TestResult {
    for &(chip, cut) in PROFILES {
        let mut state = Ddv::default();
        let mut io = Model::new();
        let mut output = [0; 2];
        if ready(state.read(&mut io, chip, cut, 0x5ea, &mut output)) != Some(Ok(()))
            || output != [0x21, 0x43]
            || state.is_terminal()
        {
            return TestResult::Fail("physical ECV bytes/completed ownership");
        }
        let mut expected = Vec::new();
        if chip == ChipId::Rtl8852A {
            expected.push((32, 0x38, 0));
        } else {
            expected.extend_from_slice(&[
                (8, 0xcc, 4),
                (16, 0, 0x4000),
                (16, 0, 0xc000),
                (16, 0, 0xc000),
            ]);
            if chip == ChipId::Rtl8852B && cut == 0 {
                expected.push((32, 0x38, 0x80000));
            }
        }
        expected.extend_from_slice(&[(32, 0x30, 0x5ea0000), (32, 0x30, 0x5eb0000)]);
        if chip != ChipId::Rtl8852A {
            if chip == ChipId::Rtl8852B && cut == 0 {
                expected.push((32, 0x38, 0));
            }
            expected.extend_from_slice(&[
                (16, 0, 0xc100),
                (16, 0, 0x4100),
                (16, 0, 0x100),
                (8, 0xcc, 0),
            ]);
        }
        let delays: &[u64] = if chip == ChipId::Rtl8852A {
            &[1, 1]
        } else {
            &[1000, 1, 1, 1000]
        };
        if io.writes != expected || io.delays != delays {
            return TestResult::Fail("Linux DDV register widths/bank/burst/isolation order");
        }
        if ready(state.read(&mut io, chip, cut, 0x5ea, &mut output)) != Some(Ok(())) {
            return TestResult::Fail("completed read cannot be reused");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ddv_completed_read_restores_exact_linux_controls
);

fn smoke_rtw89_ddv_failed_access_is_terminal_without_cleanup() -> TestResult {
    for &(chip, cut) in PROFILES {
        let mut complete = Model::new();
        let mut state = Ddv::default();
        if ready(state.read(&mut complete, chip, cut, 0x5ea, &mut [0; 2])) != Some(Ok(())) {
            return TestResult::Fail("reference DDV operation");
        }
        for at in 0..complete.operations {
            let mut io = Model::new();
            io.fail_at = Some(at);
            let mut state = Ddv::default();
            if ready(state.read(&mut io, chip, cut, 0x5ea, &mut [0; 2])) != Some(Err(Error::Access))
                || !state.is_terminal()
            {
                return TestResult::Fail("uncertain DDV access reopened ownership");
            }
            if io.operations != at + 1 {
                return TestResult::Fail("cleanup touched hardware after failed access");
            }
            let before = io.operations;
            if ready(state.read(&mut io, chip, cut, 0x5ea, &mut [0; 2]))
                != Some(Err(Error::Terminal))
                || io.operations != before
            {
                return TestResult::Fail("failed read replayed controller operation");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ddv_failed_access_is_terminal_without_cleanup
);

fn smoke_rtw89_ddv_timeout_and_cancel_require_reset() -> TestResult {
    for &(chip, cut) in PROFILES {
        let mut io = Model::new();
        io.stall = true;
        let mut state = Ddv::default();
        let mut out = [0xa5];
        if ready(state.read(&mut io, chip, cut, 0x5ea, &mut out)) != Some(Err(Error::Timeout))
            || !state.is_terminal()
            || out != [0xa5]
        {
            return TestResult::Fail("controller timeout retired uncertain read");
        }
        if io.writes.last() != Some(&(32, 0x30, 0x5ea0000)) {
            return TestResult::Fail("isolation cleanup mistaken for controller abort");
        }
        let before = io.operations;
        if ready(state.read(&mut io, chip, cut, 0x5ea, &mut out)) != Some(Err(Error::Terminal))
            || io.operations != before
        {
            return TestResult::Fail("timeout retry reached registers");
        }
        let mut io = Model::new();
        io.pending = true;
        let mut state = Ddv::default();
        if ready(state.read(&mut io, chip, cut, 0x5ea, &mut out)).is_some() || !state.is_terminal()
        {
            return TestResult::Fail("cancellation fixture missed real wait");
        }
        let before = io.operations;
        if ready(state.read(&mut io, chip, cut, 0x5ea, &mut out)) != Some(Err(Error::Terminal))
            || io.operations != before
        {
            return TestResult::Fail("cancelled read replayed controller operation");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ddv_timeout_and_cancel_require_reset
);
