//! Uses the actual Linux-traced power/off register model, with literal factory
//! DDV bytes and PCI config replies. No powered/Ready receipt is fabricated.
use super::{Case, Model};
use crate::rtw89::{
    cold::{Cold, Phase},
    factory::Source,
    mac::ChipId,
    pcie::Interface,
    phy_access::Generation,
    power::{Error, Io},
};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Hardware {
    inner: Model,
    chip: ChipId,
    cut: u8,
    config: Vec<u8>,
    raw: [u8; 1216],
    sequence: Vec<&'static str>,
    pending_at: Option<usize>,
}
impl Hardware {
    fn new(chip: ChipId, inherited: bool) -> Self {
        let cut = if chip == ChipId::Rtl8851B { 0 } else { 1 };
        let case = Case {
            chip: 0,
            cut,
            rfe: 0,
            valid: false,
            power_k_valid: false,
            ecv: 2,
            pad: 0,
            result_cut: cut,
            trace: &[],
        };
        let mut inner = Model::new(&case);
        if inherited {
            inner.regs[0x3f1] = 1;
        }
        inner.regs[0xa] = 32;
        let mut config = vec![0; 4096];
        config[0x34] = 0x40;
        config[0x40] = 0x10;
        config[0x42] = 2;
        config[0x82] = 1;
        let mut raw = [255; 1216];
        let mut cursor = 4;
        for (offset, bytes) in [
            (0x400, [2, 4]),
            (0x402, [6, 8]),
            (0x404, [10, 12]),
            (0x2b8, [255, 0x33]),
            (0x2ca, [5, b'U']),
            (0x2cc, [b'S', 255]),
        ] {
            let block = offset / 8;
            raw[cursor] = (block >> 4) as u8;
            raw[cursor + 1] = ((block & 15) << 4) as u8 | (15 ^ (1 << ((offset % 8) / 2)));
            raw[cursor + 2..cursor + 4].copy_from_slice(&bytes);
            cursor += 4;
        }
        Self {
            inner,
            chip,
            cut,
            config,
            raw,
            sequence: Vec::new(),
            pending_at: None,
        }
    }
    async fn pause(&self) {
        if self.pending_at == Some(self.inner.operations) {
            core::future::pending::<()>().await;
        }
    }
    fn edge(&mut self, a: u32, v: u32) {
        if (a == 4 && v & 0x100 != 0) || (a == 5 && v & 1 != 0) {
            self.sequence.push("on");
        }
        if (a == 4 && v & 0x200 != 0) || (a == 5 && v & 2 != 0) {
            self.sequence.push("off");
        }
    }
    fn cfg_read(&mut self, a: u16, width: usize) -> Result<u32, Error> {
        self.inner.access()?;
        let mut b = [0; 4];
        b[..width].copy_from_slice(&self.config[usize::from(a)..usize::from(a) + width]);
        Ok(u32::from_le_bytes(b))
    }
    fn cfg_write(&mut self, a: u16, width: usize, v: u32) -> Result<(), Error> {
        self.inner.access()?;
        self.config[usize::from(a)..usize::from(a) + width]
            .copy_from_slice(&v.to_le_bytes()[..width]);
        if a == 0x68 {
            self.sequence.push("basic");
        }
        Ok(())
    }
}
impl Io for Hardware {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        self.inner.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        self.inner.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.inner.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.edge(a, u32::from(v));
        self.inner.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.edge(a, u32::from(v));
        self.inner.write16(a, v)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.edge(a, v);
        self.inner.write32(a, v)
    }
    fn now_us(&self) -> u64 {
        self.inner.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        self.pause().await;
        self.inner.delay_us(us).await
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        self.pause().await;
        let result = self.inner.read_ecv().await?;
        if let Some(cut) = result {
            self.cut = cut;
        }
        Ok(result)
    }
}
impl Source for Hardware {
    fn profile(&self) -> (ChipId, u8) {
        (self.chip, self.cut)
    }
    async fn physical(&mut self, start: u16, output: &mut [u8]) -> Result<(), Error> {
        self.pause().await;
        self.inner.access()?;
        self.sequence.push("factory");
        match (start, output.len()) {
            (0, 1216) => output.copy_from_slice(&self.raw),
            (0x5e9, 5) => output.copy_from_slice(&[0xff, (self.cut << 4) | 15, 255, 255, 255]),
            _ => panic!("incomplete physical factory read"),
        };
        Ok(())
    }
}
impl Interface for Hardware {
    async fn config_read8(&mut self, a: u16) -> Result<u8, Error> {
        self.pause().await;
        self.cfg_read(a, 1).map(|v| v as u8)
    }
    async fn config_read16(&mut self, a: u16) -> Result<u16, Error> {
        self.pause().await;
        self.cfg_read(a, 2).map(|v| v as u16)
    }
    async fn config_read32(&mut self, a: u16) -> Result<u32, Error> {
        self.pause().await;
        self.cfg_read(a, 4)
    }
    async fn config_write8(&mut self, a: u16, v: u8) -> Result<(), Error> {
        self.pause().await;
        self.cfg_write(a, 1, u32::from(v))
    }
    async fn config_write16(&mut self, a: u16, v: u16) -> Result<(), Error> {
        self.pause().await;
        self.cfg_write(a, 2, u32::from(v))
    }
    async fn phy_read(&mut self, _: Generation, _: u8) -> Result<u16, Error> {
        panic!("basic_cfg does not need MDIO")
    }
    async fn phy_write(&mut self, _: Generation, _: u8, _: u16) -> Result<(), Error> {
        panic!("basic_cfg does not need MDIO")
    }
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut f = pin!(future);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(r) => Some(r),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_cold_power_factory_basic_and_qualified_runtime_power() -> TestResult {
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        for inherited in [false, true] {
            let mut cold = Cold::new(Hardware::new(chip, inherited));
            // SAFETY: inert exclusive model never has physical DMA or IRQ activity.
            if ready(unsafe { cold.prepare() }) != Some(Ok(())) || cold.phase() != Phase::Ready {
                return TestResult::Fail("actual cold initialization did not complete");
            }
            let id = cold.identity().unwrap();
            if id.chip() != chip
                || id.cut() != if chip == ChipId::Rtl8851B { 2 } else { 1 }
                || id.calibration().rfe_type != 5
                || !id.calibration().valid
                || id.calibration().power_k_valid
            {
                return TestResult::Fail("cold power detached actual RFE/power-k/corrected cut");
            }
            // SAFETY: same model; completed cold initialization must not replay.
            if ready(unsafe { cold.prepare() }) != Some(Err(crate::rtw89::cold::Error::Terminal)) {
                return TestResult::Fail("cold initialization replayed after readiness");
            }
            let (prepared, _, factory) = match cold.into_prepared() {
                Ok(p) => p.into_parts(),
                Err(_) => return TestResult::Fail("completed cold owner did not transfer backend"),
            };
            let expected = if inherited {
                &["off", "on", "factory", "factory", "off", "basic", "on"][..]
            } else {
                &["on", "factory", "factory", "off", "basic", "on"][..]
            };
            if prepared.sequence != expected || factory.identity().unwrap().cut() != id.cut() {
                return TestResult::Fail("factory/power-off/basic/runtime power ordering changed");
            }
            if chip == ChipId::Rtl8851B
                && prepared
                    .inner
                    .trace
                    .iter()
                    .filter(|(width, _, _)| *width == 255)
                    .count()
                    != 1
            {
                return TestResult::Fail("corrected ECV cut was reread or defaulted");
            }
            if chip == ChipId::Rtl8852B {
                let writes: Vec<_> = prepared
                    .inner
                    .trace
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| {
                        entry.0 == 16 && entry.1 == crate::rtw89::power_regs::R_AX_SPS_ANA_ON_CTRL2
                    })
                    .collect();
                if writes.len() != 1 {
                    return TestResult::Fail(
                        "qualified RFE5 was applied to discovery power or omitted at runtime",
                    );
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_cold_power_factory_basic_and_qualified_runtime_power
);
fn smoke_rtw89_cold_failure_and_cancellation_never_publish_identity() -> TestResult {
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        let mut baseline = Cold::new(Hardware::new(chip, false));
        // SAFETY: exclusive model supplies the actual power callback baseline.
        if ready(unsafe { baseline.prepare() }) != Some(Ok(())) {
            return TestResult::Fail("cold failure baseline");
        }
        let total = baseline
            .into_prepared()
            .unwrap()
            .into_parts()
            .0
            .inner
            .operations;
        for edge in 0..total {
            for cancel in [false, true] {
                let mut hardware = Hardware::new(chip, false);
                if cancel {
                    hardware.pending_at = Some(edge);
                } else {
                    hardware.inner.fail_at = Some(edge);
                }
                let mut cold = Cold::new(hardware);
                // SAFETY: faults/cancellation affect only this inert retained model.
                let result = ready(unsafe { cold.prepare() });
                if cancel && result == Some(Ok(())) {
                    continue;
                }
                if result == Some(Ok(()))
                    || matches!(cold.phase(), Phase::New | Phase::Ready)
                    || cold.identity().is_some()
                {
                    return TestResult::Fail("uncertain cold initialization published readiness");
                }
                // SAFETY: same exclusive model; terminal retry must reject.
                if ready(unsafe { cold.prepare() })
                    != Some(Err(crate::rtw89::cold::Error::Terminal))
                {
                    return TestResult::Fail("uncertain cold initialization replayed");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_cold_failure_and_cancellation_never_publish_identity
);
