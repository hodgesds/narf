//! Exact Linux C traces plus cancellation/authority fault injection.
use super::{
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
    include!("power/golden.rs");
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
            self.regs[5] &= !1;
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

fn smoke_rtw89_power_matches_linux_native_callbacks() -> TestResult {
    for case in golden::CASES {
        let mut power = Power::new(Model::new(case));
        if ready(power.power_on(chip(case), case.cut, cal(case))) != Some(Ok(case.result_cut))
            || power.phase() != Phase::Powered
        {
            return TestResult::Fail("Linux power callback completion/corrected cut");
        }
        if power.io().trace != case.trace {
            return TestResult::Fail("independent C/Linux power register trace");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_power_matches_linux_native_callbacks
);

fn smoke_rtw89_power_authority_failure_cannot_replay() -> TestResult {
    for case in golden::CASES {
        let mut complete = Power::new(Model::new(case));
        if ready(complete.power_on(chip(case), case.cut, cal(case))) != Some(Ok(case.result_cut)) {
            return TestResult::Fail("reference callback");
        }
        let operations = complete.io().operations;
        for at in 0..operations {
            let mut model = Model::new(case);
            model.fail_at = Some(at);
            let mut power = Power::new(model);
            if ready(power.power_on(chip(case), case.cut, cal(case))) != Some(Err(Error::Access))
                || power.phase() != Phase::Starting
            {
                return TestResult::Fail("failed access did not close power attempt");
            }
            let before = power.io().operations;
            if ready(power.power_on(chip(case), case.cut, cal(case))) != Some(Err(Error::Terminal))
                || power.io().operations != before
            {
                return TestResult::Fail("partial power replay reached hardware");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_power_authority_failure_cannot_replay
);

fn smoke_rtw89_power_cancel_timeout_and_inherited_state() -> TestResult {
    for case in golden::CASES {
        let mut model = Model::new(case);
        model.hold_onmac = true;
        model.pending = true;
        let mut power = Power::new(model);
        if ready(power.power_on(chip(case), case.cut, cal(case))).is_some()
            || power.phase() != Phase::Starting
        {
            return TestResult::Fail("cancel fixture did not reach real power wait");
        }
        let before = power.io().operations;
        if ready(power.power_on(chip(case), case.cut, cal(case))) != Some(Err(Error::Terminal))
            || power.io().operations != before
        {
            return TestResult::Fail("cancelled attempt replayed power commands");
        }
        let mut model = Model::new(case);
        model.hold_onmac = true;
        let mut power = Power::new(model);
        if ready(power.power_on(chip(case), case.cut, cal(case))) != Some(Err(Error::Timeout))
            || power.phase() != Phase::Starting
        {
            return TestResult::Fail("unbounded/stale power wait");
        }
        let mut model = Model::new(case);
        model.regs[0x3f1] = 1;
        let mut power = Power::new(model);
        if ready(power.power_on(chip(case), case.cut, cal(case))) != Some(Err(Error::AlreadyOn))
            || !power.io().trace.is_empty()
        {
            return TestResult::Fail("inherited powered MAC accepted as a fresh reset");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_power_cancel_timeout_and_inherited_state
);
