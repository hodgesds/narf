use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Case {
    chip: ChipId,
    seed: u8,
    trace: &'static [(u32, u32)],
}
include!("fifo/golden.rs");
struct Model {
    regs: Vec<u8>,
    trace: Vec<(u32, u32)>,
    now: u64,
    operations: usize,
    fail: Option<usize>,
    stuck: Option<u32>,
    pending: bool,
}
impl Model {
    fn new(seed: u8) -> Self {
        let mut m = Self {
            regs: vec![seed; 65536],
            trace: Vec::new(),
            now: 0,
            operations: 0,
            fail: None,
            stuck: None,
            pending: false,
        };
        m.regs[R_AX_WDE_INI_STATUS as usize..R_AX_WDE_INI_STATUS as usize + 4]
            .copy_from_slice(&WDE_MGN_INI_RDY.to_le_bytes());
        m.regs[R_AX_PLE_INI_STATUS as usize..R_AX_PLE_INI_STATUS as usize + 4]
            .copy_from_slice(&PLE_MGN_INI_RDY.to_le_bytes());
        m
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
}
impl Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, Error> {
        Err(Error::Unsupported)
    }
    fn read16(&mut self, _: u32) -> Result<u16, Error> {
        Err(Error::Unsupported)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.access()?;
        if self.stuck == Some(a) {
            return Ok(0);
        };
        Ok(u32::from_le_bytes(
            self.regs[a as usize..a as usize + 4].try_into().unwrap(),
        ))
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        self.trace.push((a, v));
        self.regs[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += us;
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
fn smoke_rtw89_fifo_linux_traces_and_failed_access_retention() -> TestResult {
    for c in CASES {
        let mut owner = Fifo::default();
        let mut io = Model::new(c.seed);
        // SAFETY: owned register model has no PCI/DMA/IRQ/firmware producers.
        if ready(unsafe { owner.prepare(&mut io, c.chip) }) != Some(Ok(()))
            || owner.state() != State::Ready
            || io.trace != c.trace
        {
            return TestResult::Fail("independent Linux DLE/HFC full trace");
        }
        let total = io.operations;
        for at in 0..total {
            let mut owner = Fifo::default();
            let mut io = Model::new(c.seed);
            io.fail = Some(at);
            // SAFETY: inert owned model, including failed accesses.
            if ready(unsafe { owner.prepare(&mut io, c.chip) }) != Some(Err(Error::Access))
                || owner.state() != State::Configuring
            {
                return TestResult::Fail("partial FIFO configuration reopened owner");
            }
            let before = io.operations;
            // SAFETY: terminal model may not access registers again.
            if ready(unsafe { owner.prepare(&mut io, c.chip) }) != Some(Err(Error::Terminal))
                || io.operations != before
            {
                return TestResult::Fail("failed FIFO attempt replayed publication");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_fifo_linux_traces_and_failed_access_retention
);
fn smoke_rtw89_fifo_ready_timeout_cancel_and_gone() -> TestResult {
    for c in CASES {
        for address in [R_AX_WDE_INI_STATUS, R_AX_PLE_INI_STATUS] {
            for pending in [false, true] {
                let mut owner = Fifo::default();
                let mut io = Model::new(c.seed);
                io.stuck = Some(address);
                io.pending = pending;
                // SAFETY: inert owned model; a Pending result is intentionally dropped.
                if ready(unsafe { owner.prepare(&mut io, c.chip) })
                    != if pending {
                        None
                    } else {
                        Some(Err(Error::Timeout))
                    }
                    || owner.state() != State::Configuring
                {
                    return TestResult::Fail("DLE readiness deadline/cancel ownership");
                }
                let before = io.operations;
                // SAFETY: terminal state must reject before register access.
                if ready(unsafe { owner.prepare(&mut io, c.chip) }) != Some(Err(Error::Terminal))
                    || io.operations != before
                {
                    return TestResult::Fail("cancelled DLE wait rearmed FIFO");
                }
            }
            let mut owner = Fifo::default();
            let mut io = Model::new(c.seed);
            io.regs[address as usize..address as usize + 4].fill(255);
            // SAFETY: inert owned model of absent hardware readback.
            if ready(unsafe { owner.prepare(&mut io, c.chip) }) != Some(Err(Error::Gone))
                || owner.state() != State::Configuring
            {
                return TestResult::Fail("all-ones DLE status treated as ready");
            }
        }
    }
    let mut owner = Fifo::default();
    let mut io = Model::new(0);
    // SAFETY: no hardware and unsupported-chip rejection must precede all access.
    if ready(unsafe { owner.prepare(&mut io, ChipId::Rtl8922A) }) != Some(Err(Error::Unsupported))
        || io.operations != 0
        || owner.state() != State::New
    {
        return TestResult::Fail("BE used incompatible AX FIFO layout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_fifo_ready_timeout_cancel_and_gone
);
