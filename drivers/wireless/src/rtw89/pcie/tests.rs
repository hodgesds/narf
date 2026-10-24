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
    cut: u8,
    seed: u8,
    generation: u8,
    ber: bool,
    trace: &'static [(u8, u32, u32)],
}
include!("golden.rs");
struct Model {
    chip: ChipId,
    memory: Vec<u8>,
    trace: Vec<(u8, u32, u32)>,
    operations: usize,
    fail: Option<usize>,
    pending: Option<usize>,
    gone: bool,
    ignore: bool,
}
impl Model {
    fn new(chip: ChipId, seed: u8, generation: u8) -> Self {
        let mut memory = vec![seed; 0x201000];
        memory[0x200082] = generation;
        if seed != 0 {
            memory[0x200719] |= 8;
        }
        Self {
            chip,
            memory,
            trace: Vec::new(),
            operations: 0,
            fail: None,
            pending: None,
            gone: false,
            ignore: false,
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
        if self.gone {
            return Ok(match width {
                8 => 255,
                16 => 65535,
                _ => u32::MAX,
            });
        }
        let mut b = [0; 4];
        b[..usize::from(width / 8)]
            .copy_from_slice(&self.memory[a as usize..a as usize + usize::from(width / 8)]);
        Ok(u32::from_le_bytes(b))
    }
    fn write(&mut self, a: u32, width: u8, v: u32) -> Result<(), Error> {
        self.access()?;
        self.trace.push((width, a, v));
        if !self.ignore {
            self.memory[a as usize..a as usize + usize::from(width / 8)]
                .copy_from_slice(&v.to_le_bytes()[..usize::from(width / 8)]);
        }
        Ok(())
    }
    fn phy_address(&self, g: Generation, a: u8) -> u32 {
        let offset = if g == Generation::One { 0 } else { 1 };
        if self.chip == ChipId::Rtl8852C {
            0x3800 + offset * 0x80 + u32::from(a) * 2
        } else {
            0x100000 + offset * 0x10000 + u32::from(a) * 2
        }
    }
    async fn pause(&mut self) {
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
    async fn config_write8(&mut self, a: u16, v: u8) -> Result<(), Error> {
        self.pause().await;
        self.write8(0x200000 + u32::from(a), v)
    }
    async fn phy_read(&mut self, g: Generation, a: u8) -> Result<u16, Error> {
        self.pause().await;
        self.read16(self.phy_address(g, a))
    }
    async fn phy_write(&mut self, g: Generation, a: u8, v: u16) -> Result<(), Error> {
        self.pause().await;
        self.write16(self.phy_address(g, a), v)
    }
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut f = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(r) => Some(r),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_pcie_preinit_and_mode_match_linux() -> TestResult {
    for case in CASES {
        let mut model = Model::new(case.chip, case.seed, case.generation);
        let mut owner = Pcie::default();
        // SAFETY: all register/config/PHY addresses belong to the inert model.
        if ready(unsafe { owner.prepare(&mut model, case.chip, case.cut, case.ber) })
            != Some(Ok(()))
            || owner.state() != State::Ready
            || mode(&mut model, case.chip, case.cut).is_err()
            || model.trace != case.trace
        {
            return TestResult::Fail("AX PCIe pre-init/mode differs from independent Linux C");
        }
        let before = model.operations;
        // SAFETY: same exclusive model; completed owner must reject before I/O.
        if ready(unsafe { owner.prepare(&mut model, case.chip, case.cut, case.ber) })
            != Some(Err(Error::Terminal))
            || model.operations != before
        {
            return TestResult::Fail("PCIe ready owner replayed policy");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pcie_preinit_and_mode_match_linux
);
fn smoke_rtw89_pcie_preinit_failure_and_cancel_are_terminal() -> TestResult {
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        let mut baseline = Model::new(chip, 0xa5, 2);
        let mut owner = Pcie::default();
        // SAFETY: exclusive inert model with no real PCI device or DMA.
        if ready(unsafe { owner.prepare(&mut baseline, chip, 0, false) }) != Some(Ok(())) {
            return TestResult::Fail("PCIe failure baseline");
        }
        for failure in 0..baseline.operations {
            let mut model = Model::new(chip, 0xa5, 2);
            model.fail = Some(failure);
            let mut owner = Pcie::default();
            // SAFETY: injected failure touches only private model memory.
            if ready(unsafe { owner.prepare(&mut model, chip, 0, false) }).is_none_or(|r| r.is_ok())
                || owner.state() != State::Preparing
            {
                return TestResult::Fail("failed PCIe policy became reusable");
            }
            let before = model.operations;
            // SAFETY: same model, terminal retry must have no side effect.
            if ready(unsafe { owner.prepare(&mut model, chip, 0, false) })
                != Some(Err(Error::Terminal))
                || model.operations != before
            {
                return TestResult::Fail("failed PCIe owner replayed access");
            }
        }
        // Hold every asynchronous PHY/config edge in turn. Synchronous MMIO
        // cannot cancel between polls; it is covered by injected access errors.
        for edge in 0..baseline.operations {
            let mut model = Model::new(chip, 0xa5, 2);
            model.pending = Some(edge);
            let mut owner = Pcie::default();
            // SAFETY: dropped future can retain only this model's policy state.
            let result = ready(unsafe { owner.prepare(&mut model, chip, 0, false) });
            if result.is_none() {
                let before = model.operations;
                // SAFETY: cancellation must reject the same model before I/O.
                let retry = ready(unsafe { owner.prepare(&mut model, chip, 0, false) });
                if owner.state() != State::Preparing
                    || retry != Some(Err(Error::Terminal))
                    || model.operations != before
                {
                    return TestResult::Fail("cancelled PCIe transaction reopened policy");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pcie_preinit_failure_and_cancel_are_terminal
);
fn smoke_rtw89_pcie_rejects_unknown_profile_and_phy_rate() -> TestResult {
    for generation in [0, 3, 255] {
        let mut model = Model::new(ChipId::Rtl8852B, 0, generation);
        let mut owner = Pcie::default();
        // SAFETY: invalid-rate fixture is exclusively owned and inert.
        if ready(unsafe { owner.prepare(&mut model, ChipId::Rtl8852B, 0, false) })
            != Some(Err(Error::Unsupported))
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("unknown PCIe link rate defaulted");
        }
    }
    let mut model = Model::new(ChipId::Rtl8922A, 0, 1);
    let mut owner = Pcie::default();
    // SAFETY: unsupported BE must reject before touching this model.
    if ready(unsafe { owner.prepare(&mut model, ChipId::Rtl8922A, 0, false) })
        != Some(Err(Error::Unsupported))
        || model.operations != 0
    {
        return TestResult::Fail("BE used AX PCIe policy");
    }
    let mut model = Model::new(ChipId::Rtl8852A, 0, 1);
    model.gone = true;
    let mut owner = Pcie::default();
    // SAFETY: disappeared-device read values come only from the inert model.
    if ready(unsafe { owner.prepare(&mut model, ChipId::Rtl8852A, 0, false) })
        != Some(Err(Error::Gone))
    {
        return TestResult::Fail("missing PCIe device accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pcie_rejects_unknown_profile_and_phy_rate
);

fn smoke_rtw89_pcie_mode_rejects_ignored_programming() -> TestResult {
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        let mut model = Model::new(chip, 0, 1);
        model.ignore = true;
        if mode(&mut model, chip, 1) != Err(Error::Access) {
            return TestResult::Fail("ignored PCIe mode writes reached readiness");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pcie_mode_rejects_ignored_programming
);
