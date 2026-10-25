use super::super::phy_access::Generation;
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
    generation: u8,
    seed: u8,
    host: bool,
    calibrated: bool,
    trace: &'static [(u8, u32, u32)],
}
include!("golden.rs");
struct Model {
    memory: Vec<u8>,
    trace: Vec<(u8, u32, u32)>,
    operations: usize,
    fail: Option<usize>,
    pending: Option<usize>,
    ignore: bool,
}
impl Model {
    fn new(generation: u8, seed: u8, host: bool, calibrated: bool) -> Self {
        let mut memory = vec![seed; 0x11000];
        memory[0x10000..].fill(0);
        memory[0x10034] = 0x40;
        memory[0x10040] = 0x10;
        memory[0x10042] = 2;
        memory[0x10082] = generation;
        memory[0x10050] = if host { 2 } else { 0 };
        memory[0x10051] = u8::from(host);
        for offset in [0x68, 0x70f, 0x719, 0x718] {
            memory[0x10000 + offset] = seed;
        }
        if host {
            memory[0x10100..0x10104].copy_from_slice(&0x16010001u32.to_le_bytes());
            memory[0x10160..0x10164].copy_from_slice(&0x1001eu32.to_le_bytes());
            memory[0x10168] = 15;
        }
        if calibrated {
            for a in [0x3812, 0x3892] {
                memory[a] |= 16;
            }
        }
        Self {
            memory,
            trace: Vec::new(),
            operations: 0,
            fail: None,
            pending: None,
            ignore: false,
        }
    }
    fn index(a: u32) -> usize {
        if a >= 0x200000 {
            0x10000 + (a - 0x200000) as usize
        } else {
            a as usize
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let op = self.operations;
        self.operations += 1;
        if self.fail == Some(op) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, a: u32, width: u8) -> Result<u32, Error> {
        self.access()?;
        let at = Self::index(a);
        let mut bytes = [0; 4];
        bytes[..usize::from(width / 8)]
            .copy_from_slice(&self.memory[at..at + usize::from(width / 8)]);
        Ok(u32::from_le_bytes(bytes))
    }
    fn write(&mut self, a: u32, width: u8, value: u32) -> Result<(), Error> {
        self.access()?;
        self.trace.push((width, a, value));
        let at = Self::index(a);
        if !self.ignore {
            self.memory[at..at + usize::from(width / 8)]
                .copy_from_slice(&value.to_le_bytes()[..usize::from(width / 8)]);
        }
        Ok(())
    }
    async fn pause(&self) {
        if self.pending == Some(self.operations) {
            core::future::pending::<()>().await;
        }
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        self.read(a, 8).map(|v| v as u8)
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        self.read(a, 16).map(|v| v as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.read(a, 32)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.write(a, 8, u32::from(v))
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.write(a, 16, u32::from(v))
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.write(a, 32, v)
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
impl Interface for Model {
    async fn config_read8(&mut self, a: u16) -> Result<u8, Error> {
        self.pause().await;
        self.read8(0x200000 + u32::from(a))
    }
    async fn config_read16(&mut self, a: u16) -> Result<u16, Error> {
        self.pause().await;
        self.read16(0x200000 + u32::from(a))
    }
    async fn config_read32(&mut self, a: u16) -> Result<u32, Error> {
        self.pause().await;
        self.read32(0x200000 + u32::from(a))
    }
    async fn config_write8(&mut self, a: u16, v: u8) -> Result<(), Error> {
        self.pause().await;
        self.write8(0x200000 + u32::from(a), v)
    }
    async fn config_write16(&mut self, a: u16, v: u16) -> Result<(), Error> {
        self.pause().await;
        self.write16(0x200000 + u32::from(a), v)
    }
    async fn phy_read(&mut self, _: Generation, _: u8) -> Result<u16, Error> {
        panic!("basic_cfg uses only direct C RAC")
    }
    async fn phy_write(&mut self, _: Generation, _: u8, _: u16) -> Result<(), Error> {
        panic!("basic_cfg uses only direct C RAC")
    }
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut f = pin!(future);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(r) => Some(r),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_pci_basic_matches_frozen_references_policy() -> TestResult {
    for case in CASES {
        let mut model = Model::new(case.generation, case.seed, case.host, case.calibrated);
        let mut owner = Basic::default();
        // SAFETY: BAR/ECAM/RAC belong only to this inert independently traced model.
        if ready(unsafe { owner.prepare(&mut model, case.chip) }) != Some(Ok(()))
            || owner.state() != State::Ready
            || model.trace != case.trace
        {
            return TestResult::Fail("PCI basic_cfg differs from the frozen reference");
        }
        let before = model.operations;
        // SAFETY: same model; a ready owner must not replay configuration.
        if ready(unsafe { owner.prepare(&mut model, case.chip) }) != Some(Err(Error::Terminal))
            || model.operations != before
        {
            return TestResult::Fail("PCI basic_cfg replayed after readiness");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pci_basic_matches_frozen_references_policy
);
fn smoke_rtw89_pci_basic_errors_and_cancellation_remain_terminal() -> TestResult {
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        let mut baseline = Model::new(2, 0xa5, true, false);
        let mut owner = Basic::default();
        // SAFETY: exclusive inert model with all current host PM flags enabled.
        if ready(unsafe { owner.prepare(&mut baseline, chip) }) != Some(Ok(())) {
            return TestResult::Fail("basic_cfg failure baseline");
        }
        for edge in 0..baseline.operations {
            for cancel in [false, true] {
                let mut model = Model::new(2, 0xa5, true, false);
                if cancel {
                    model.pending = Some(edge);
                } else {
                    model.fail = Some(edge);
                }
                let mut owner = Basic::default();
                // SAFETY: only private memory is affected by injected failures/cancellation.
                let result = ready(unsafe { owner.prepare(&mut model, chip) });
                if cancel && result == Some(Ok(())) {
                    continue;
                }
                if result == Some(Ok(())) || owner.state() != State::Preparing {
                    return TestResult::Fail("uncertain basic_cfg reached readiness");
                }
                let before = model.operations;
                // SAFETY: terminal retry must reject before any model access.
                let retry = ready(unsafe { owner.prepare(&mut model, chip) });
                if retry != Some(Err(Error::Terminal)) || model.operations != before {
                    return TestResult::Fail("uncertain basic_cfg owner replayed");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pci_basic_errors_and_cancellation_remain_terminal
);
fn smoke_rtw89_pci_basic_checks_capability_chains_and_programming() -> TestResult {
    for pointer in [0, 0x3c, 0x41, 0xdc, 0xfc] {
        let mut model = Model::new(1, 0, false, false);
        model.memory[0x10034] = pointer;
        let mut owner = Basic::default();
        // SAFETY: malformed ECAM metadata resides entirely in the inert model.
        if ready(unsafe { owner.prepare(&mut model, ChipId::Rtl8852A) }).is_none_or(|r| r.is_ok())
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("invalid PCI capability pointer accepted");
        }
    }
    for extended in [false, true] {
        let mut model = Model::new(1, 0, true, false);
        if extended {
            model.memory[0x10100..0x10104].copy_from_slice(&0x10010001u32.to_le_bytes());
        } else {
            model.memory[0x10040] = 1;
            model.memory[0x10041] = 0x40;
        }
        let mut owner = Basic::default();
        // SAFETY: cyclic linked lists are private fixture bytes, not live ECAM.
        if ready(unsafe { owner.prepare(&mut model, ChipId::Rtl8852B) }) != Some(Err(Error::Access))
        {
            return TestResult::Fail("cyclic PCI capability list was not bounded");
        }
    }
    let mut model = Model::new(1, 0, false, false);
    model.ignore = true;
    let mut owner = Basic::default();
    // SAFETY: ignored control writes are generated only by this inert model.
    if ready(unsafe { owner.prepare(&mut model, ChipId::Rtl8852A) }) != Some(Err(Error::Access)) {
        return TestResult::Fail("ignored Device Control2 programming accepted");
    }
    for rate in [0, 3, 255] {
        let mut model = Model::new(rate, 0, false, false);
        let mut owner = Basic::default();
        // SAFETY: invalid C PHY-rate bytes cannot address any real device.
        if ready(unsafe { owner.prepare(&mut model, ChipId::Rtl8852C) }).is_none_or(|r| r.is_ok()) {
            return TestResult::Fail("unsupported C link rate defaulted");
        }
    }
    let mut model = Model::new(1, 0, false, false);
    let mut owner = Basic::default();
    // SAFETY: unsupported BE must reject before touching this AX fixture.
    if ready(unsafe { owner.prepare(&mut model, ChipId::Rtl8922A) })
        != Some(Err(Error::Unsupported))
        || model.operations != 0
    {
        return TestResult::Fail("BE used AX PCI basic policy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pci_basic_checks_capability_chains_and_programming
);
