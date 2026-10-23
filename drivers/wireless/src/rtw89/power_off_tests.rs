//! Exact Linux C traces plus cancellation/authority fault injection.
use crate::rtw89::{
    mac::ChipId,
    power::{Calibration, Error, Io, Phase, Power},
};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Case {
    chip: u8,
    cut: u8,
    rfe: u8,
    valid: bool,
    power_k_valid: bool,
    ecv: u8,
    pad: u8,
    result_cut: u8,
    trace: &'static [(u8, u32, u32)],
}
mod golden {
    use super::Case;
    include!("power/off_golden.rs");
}

#[derive(Debug)]
struct Model {
    regs: Vec<u8>,
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    ecv: u8,
    operations: usize,
    fail_at: Option<usize>,
    hold_onmac: bool,
    pending: bool,
}
impl Model {
    fn new(case: &Case) -> Self {
        let mut regs = vec![0; 65536];
        regs[4..8].copy_from_slice(&(1u32 << 17).to_le_bytes());
        regs[0xf4..0xf8].copy_from_slice(&(u32::from(case.pad) << 3).to_le_bytes());
        Self {
            regs,
            trace: Vec::new(),
            now: 0,
            ecv: case.ecv,
            operations: 0,
            fail_at: None,
            hold_onmac: false,
            pending: false,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let at = self.operations;
        self.operations += 1;
        if self.fail_at == Some(at) {
            return Err(Error::Access);
        }
        Ok(())
    }
    fn write(&mut self, width: u8, address: u32, value: u32) -> Result<(), Error> {
        self.access()?;
        self.trace.push((width, address, value));
        let count = usize::from(width / 8);
        self.regs[address as usize..address as usize + count]
            .copy_from_slice(&value.to_le_bytes()[..count]);
        if !self.hold_onmac && (address == 4 || address == 5) {
            self.regs[5] &= !3;
            let raw = if address == 5 { value << 8 } else { value };
            if raw & 0x200 != 0 {
                self.regs[0x3f1] = 0;
            }
            if raw & 0x100 != 0 {
                self.regs[0x3f1] = 1;
            }
        }
        if address == 0x270 {
            self.regs[0x273] &= !0x80;
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
        Ok(u32::from_le_bytes(
            self.regs[a as usize..a as usize + 4].try_into().unwrap(),
        ))
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
        self.now += us;
        self.trace.push((0, 0, us as u32));
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        self.access()?;
        self.trace.push((255, 0, u32::from(self.ecv)));
        Ok(Some(self.ecv))
    }
}
fn chip(case: &Case) -> ChipId {
    match case.chip {
        0 => ChipId::Rtl8852A,
        1 => ChipId::Rtl8852B,
        2 => ChipId::Rtl8852C,
        _ => ChipId::Rtl8851B,
    }
}
fn cal(case: &Case) -> Calibration {
    Calibration {
        rfe_type: case.rfe,
        valid: case.valid,
        power_k_valid: case.power_k_valid,
    }
}
fn ready<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

fn powered(case: &Case) -> Power<Model> {
    let mut power = Power::new(Model::new(case));
    power.phase = Phase::Powered;
    power.profile = Some((chip(case), case.cut, cal(case)));
    power.io().regs[0x3f1] = 1;
    power
}
fn smoke_rtw89_power_off_linux_and_retained_lifecycle() -> TestResult {
    for case in golden::CASES {
        let mut p = powered(case);
        // SAFETY: owned register model has no device, IRQ or DMA producers.
        if ready(unsafe { p.power_off() }) != Some(Ok(()))
            || p.phase() != Phase::Off
            || p.io().trace != case.trace
        {
            return TestResult::Fail("Linux C power-off trace/verified OFF");
        }
        let operations = p.io().operations;
        for at in 0..operations {
            let mut q = powered(case);
            q.io().fail_at = Some(at);
            // SAFETY: same inert owned model.
            if ready(unsafe { q.power_off() }) != Some(Err(Error::Access))
                || q.phase() != Phase::Stopping
            {
                return TestResult::Fail("failed off operation lost retained stopping state");
            }
            let before = q.io().operations;
            // SAFETY: same inert owned model; terminal path must not access it.
            if ready(unsafe { q.power_off() }) != Some(Err(Error::Terminal))
                || q.io().operations != before
            {
                return TestResult::Fail("failed power-off replay reached hardware");
            }
        }
        let before = p.io().operations;
        if ready(p.power_on(ChipId::Rtl8922A, case.cut, cal(case))) != Some(Err(Error::Unsupported))
            || p.io().operations != before
        {
            return TestResult::Fail("powered profile changed across verified off");
        }
        // Old A ON fixtures expect ready bit17, retained by the OFF sequence.
        if ready(p.power_on(chip(case), case.cut, cal(case)))
            != Some(Ok(if case.chip == 3 && case.cut == 0 {
                case.ecv
            } else {
                case.cut
            }))
        {
            return TestResult::Fail("verified off refused same-profile cold restart");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_power_off_linux_and_retained_lifecycle
);
fn smoke_rtw89_power_off_cancel_timeout_and_inherited_normalize() -> TestResult {
    for case in golden::CASES {
        let mut q = powered(case);
        q.io().hold_onmac = true;
        q.io().pending = true;
        // SAFETY: owned register model only; poll is intentionally cancelled.
        if ready(unsafe { q.power_off() }).is_some() || q.phase() != Phase::Stopping {
            return TestResult::Fail("off wait cancellation did not retain owner");
        }
        let before = q.io().operations;
        // SAFETY: terminal model must reject without hardware access.
        if ready(unsafe { q.power_off() }) != Some(Err(Error::Terminal))
            || q.io().operations != before
        {
            return TestResult::Fail("cancelled power-off restarted");
        }
        let mut q = powered(case);
        q.io().hold_onmac = true;
        // SAFETY: inert register model.
        if ready(unsafe { q.power_off() }) != Some(Err(Error::Timeout))
            || q.phase() != Phase::Stopping
        {
            return TestResult::Fail("off callback wait was unbounded");
        }
        let mut q = Power::new(Model::new(case));
        q.io().regs[0x3f1] = 1;
        // SAFETY: inherited state is modelled without any DMA or IRQ owners.
        if ready(unsafe { q.normalize_inherited(chip(case), case.cut, cal(case)) })
            != Some(Ok(if case.chip == 3 && case.cut == 0 {
                case.ecv
            } else {
                case.cut
            }))
            || q.phase() != Phase::Powered
        {
            return TestResult::Fail("inherited ON normalization failed");
        }
        let mut q = Power::new(Model::new(case));
        q.io().regs[0x3f1] = 2;
        // SAFETY: inert register model of an unknown transitional state.
        if ready(unsafe { q.normalize_inherited(chip(case), case.cut, cal(case)) })
            != Some(Err(Error::AlreadyOn))
            || !q.io().trace.is_empty()
            || q.phase() != Phase::Stopping
        {
            return TestResult::Fail("unknown inherited power state was treated as cold");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_power_off_cancel_timeout_and_inherited_normalize
);
