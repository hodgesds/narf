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
include!("golden.rs");

struct Model {
    chip: ChipId,
    words: Vec<u32>,
    trace: Vec<(u32, u32)>,
    operations: usize,
    fail_at: Option<usize>,
    ignore: Option<u32>,
    busy: Option<(u32, u32)>,
    dirty_index: Option<u32>,
    gone: bool,
    stuck_reset: bool,
    pending: bool,
    now: u64,
}
impl Model {
    fn new(chip: ChipId, seed: u8) -> Self {
        let profile = Profile::for_chip(chip).unwrap();
        let mut words = vec![u32::from(seed) * 0x0101_0101; 16384];
        words[BUSY1 as usize / 4] = 0;
        words[profile.rx_busy as usize / 4] = 0;
        if profile.tx_busy2 != 0 {
            words[profile.tx_busy2 as usize / 4] = 0;
        }
        let addresses = addr_set_for_chip(chip);
        for ring in &addresses.tx {
            words[ring.idx as usize / 4] = 0x0123_0456;
        }
        for ring in &addresses.rx {
            words[ring.idx as usize / 4] = 0x0789_0abc;
        }
        Self {
            chip,
            words,
            trace: Vec::new(),
            operations: 0,
            fail_at: None,
            ignore: None,
            busy: None,
            dirty_index: None,
            gone: false,
            stuck_reset: false,
            pending: false,
            now: 0,
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
    fn clear(&mut self, index: u32) {
        if self.dirty_index != Some(index) {
            self.words[index as usize / 4] = 0;
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
    fn write8(&mut self, _: u32, _: u8) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.access()?;
        if self.gone {
            return Ok(u32::MAX);
        }
        if a == INIT && !self.stuck_reset {
            self.words[a as usize / 4] &= !RESET;
        }
        let mut value = self.words[a as usize / 4];
        if let Some((address, mask)) = self.busy {
            if a == address {
                value |= mask;
            }
        }
        Ok(value)
    }
    fn write32(&mut self, a: u32, value: u32) -> Result<(), Error> {
        self.access()?;
        self.trace.push((a, value));
        if self.ignore == Some(a) {
            return Ok(());
        }
        self.words[a as usize / 4] = value;
        let p = Profile::for_chip(self.chip).unwrap();
        let addresses = addr_set_for_chip(self.chip);
        if a == CLEAR1 {
            for bit in 0..11 {
                if value & (1 << bit) != 0 {
                    let channel = if bit == 10 { 12 } else { bit };
                    self.clear(addresses.tx[channel].idx as u32);
                }
            }
        } else if a == p.tx_clear2 && a != 0 {
            for bit in 0..2 {
                if value & (1 << bit) != 0 {
                    self.clear(addresses.tx[10 + bit].idx as u32);
                }
            }
        } else if a == p.rx_clear {
            for bit in 0..2 {
                if value & (1 << bit) != 0 {
                    self.clear(addresses.rx[bit].idx as u32);
                }
            }
        }
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
fn once<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

fn smoke_rtw89_bdram_linux_traces_and_every_access_failure() -> TestResult {
    for case in CASES {
        let mut io = Model::new(case.chip, case.seed);
        let mut owner = Bdram::default();
        // SAFETY: inert exclusive model has no PCI, DMA, IRQ or other producer.
        if once(unsafe { owner.prepare(&mut io, case.chip) }) != Some(Ok(()))
            || owner.state() != State::Ready
            || io.trace != case.trace
        {
            return TestResult::Fail("Linux AX BDRAM/control trace or zero-index receipt");
        }
        let operations = io.operations;
        // SAFETY: the same exclusive inert model remains fenced after success;
        // this terminal retry must reject before any register operation.
        if once(unsafe { owner.prepare(&mut io, case.chip) }) != Some(Err(Error::Terminal))
            || io.operations != operations
        {
            return TestResult::Fail("successful BDRAM owner permitted a second reset");
        }
        for fail_at in 0..operations {
            let mut owner = Bdram::default();
            let mut io = Model::new(case.chip, case.seed);
            io.fail_at = Some(fail_at);
            // SAFETY: same private model including the failed transaction.
            if once(unsafe { owner.prepare(&mut io, case.chip) }) != Some(Err(Error::Access))
                || owner.state() != State::Preparing
            {
                return TestResult::Fail("failed BDRAM access was accepted or lost retention");
            }
            let count = io.operations;
            // SAFETY: failed model accesses affect no hardware; this still-owned
            // inert instance must reject a second attempt without further I/O.
            if once(unsafe { owner.prepare(&mut io, case.chip) }) != Some(Err(Error::Terminal))
                || io.operations != count
            {
                return TestResult::Fail("failed BDRAM owner replayed register operations");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_bdram_linux_traces_and_every_access_failure
);

fn smoke_rtw89_bdram_idle_reset_deadlines_and_cancel_are_terminal() -> TestResult {
    for case in CASES {
        let p = Profile::for_chip(case.chip).unwrap();
        let mut waits = vec![(BUSY1, p.tx_mask & p.tx_mask.wrapping_neg())];
        if p.tx_busy2 != 0 {
            waits.push((p.tx_busy2, 1));
        }
        waits.push((p.rx_busy, 1));
        for wait in waits.into_iter().map(Some).chain(core::iter::once(None)) {
            for cancel in [false, true] {
                let mut owner = Bdram::default();
                let mut io = Model::new(case.chip, case.seed);
                io.busy = wait;
                io.stuck_reset = wait.is_none();
                io.pending = cancel;
                // SAFETY: inert model never publishes system memory or DMA.
                let result = once(unsafe { owner.prepare(&mut io, case.chip) });
                if result
                    != if cancel {
                        None
                    } else {
                        Some(Err(Error::Timeout))
                    }
                    || owner.state() != State::Preparing
                    || (!cancel && io.now != 100)
                {
                    return TestResult::Fail(
                        "BDRAM idle/reset did not respect Linux deadline/cancellation",
                    );
                }
                let count = io.operations;
                // SAFETY: cancellation/timeout occurred only in the exclusive
                // inert model; no DMA or producer can race the rejected retry.
                if once(unsafe { owner.prepare(&mut io, case.chip) }) != Some(Err(Error::Terminal))
                    || io.operations != count
                {
                    return TestResult::Fail("cancelled/timed-out BDRAM owner reopened");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_bdram_idle_reset_deadlines_and_cancel_are_terminal
);

fn smoke_rtw89_bdram_ignored_writes_dirty_indices_and_gone_are_rejected() -> TestResult {
    for case in CASES {
        let p = Profile::for_chip(case.chip).unwrap();
        let addresses = addr_set_for_chip(case.chip);
        for channel in 0..TXCH_NUM {
            if !p.channel(channel) {
                continue;
            }
            let mut owner = Bdram::default();
            let mut io = Model::new(case.chip, case.seed);
            io.ignore = Some(addresses.tx[channel].bdram as u32);
            // SAFETY: private model; dropped hardware writes cannot affect a device.
            if once(unsafe { owner.prepare(&mut io, case.chip) }) != Some(Err(Error::Access)) {
                return TestResult::Fail("BDRAM partition write without readback was accepted");
            }
        }
        for index in addresses
            .tx
            .iter()
            .enumerate()
            .filter(|(i, _)| p.channel(*i))
            .map(|(_, r)| r.idx)
            .chain(addresses.rx.iter().map(|r| r.idx))
        {
            let mut owner = Bdram::default();
            let mut io = Model::new(case.chip, case.seed);
            io.dirty_index = Some(index as u32);
            // SAFETY: the deliberately dirty index is private model storage;
            // no real hardware, DMA, IRQ or concurrent producer exists.
            if once(unsafe { owner.prepare(&mut io, case.chip) }) != Some(Err(Error::Access))
                || owner.state() != State::Preparing
            {
                return TestResult::Fail("uncleared real hardware index admitted BDRAM readiness");
            }
        }
        let mut owner = Bdram::default();
        let mut io = Model::new(case.chip, case.seed);
        io.gone = true;
        // SAFETY: absence is synthesized by the exclusive inert register model;
        // it cannot publish DMA or change any physical device state.
        if once(unsafe { owner.prepare(&mut io, case.chip) }) != Some(Err(Error::Gone))
            || !io.trace.is_empty()
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("absent device triggered BDRAM writes or reopened owner");
        }
        let mut owner = Bdram::default();
        let mut io = Model::new(case.chip, case.seed);
        // SAFETY: private inert storage tests unsupported BE rejection before
        // any access; no actual device can receive an incompatible AX sequence.
        if once(unsafe { owner.prepare(&mut io, ChipId::Rtl8922A) })
            != Some(Err(Error::Unsupported))
            || io.operations != 0
            || owner.state() != State::New
        {
            return TestResult::Fail("BE reached AX BDRAM register access");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_bdram_ignored_writes_dirty_indices_and_gone_are_rejected
);
