use super::*;
use alloc::vec::Vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
mod offsets {
    include!("golden.rs");
}
struct SourceModel {
    chip: ChipId,
    cut: u8,
    autoload: u16,
    raw: [u8; 1216],
    extra: [u8; 5],
    reads: Vec<(u16, usize)>,
    fail: Option<usize>,
    pending: Option<usize>,
}
impl SourceModel {
    fn new(chip: ChipId) -> Self {
        let mut raw = [255; 1216];
        let mut cursor = 4;
        // Independent AX sparse records: high-block nibble followed by low
        // block/active-low word enables, then the actual little-endian word.
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
            chip,
            cut: 1,
            autoload: 32,
            raw,
            extra: [0xaa, 0x1f, 255, 255, 255],
            reads: Vec::new(),
            fail: None,
            pending: None,
        }
    }
}
impl Io for SourceModel {
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        assert_eq!(a, 0xa);
        Ok(self.autoload)
    }
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        panic!("unexpected factory byte MMIO")
    }
    fn read32(&mut self, _: u32) -> Result<u32, power::Error> {
        panic!("unexpected factory dword MMIO")
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        panic!("factory source owns DDV writes")
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        panic!("factory source owns DDV writes")
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), power::Error> {
        panic!("factory source owns DDV writes")
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        panic!("cut must come from completed power owner")
    }
}
impl Source for SourceModel {
    fn profile(&self) -> (ChipId, u8) {
        (self.chip, self.cut)
    }
    async fn physical(&mut self, start: u16, output: &mut [u8]) -> Result<(), power::Error> {
        if self.pending == Some(self.reads.len()) {
            core::future::pending::<()>().await;
        }
        if self.fail == Some(self.reads.len()) {
            return Err(power::Error::Access);
        }
        self.reads.push((start, output.len()));
        match (start, output.len()) {
            (0, 1216) => output.copy_from_slice(&self.raw),
            (0x5e9, 5) => output.copy_from_slice(&self.extra),
            _ => panic!("factory did not read complete physical proof"),
        };
        Ok(())
    }
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut f = pin!(future);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(r) => Some(r),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_factory_snapshot_matches_linux_layout_and_actual_controls() -> TestResult {
    use offsets::*;
    for (rfe, xtal, country) in [
        (A_RFE_TYPE, A_XTAL_K, A_COUNTRY_CODE),
        (B_RFE_TYPE, B_XTAL_K, B_COUNTRY_CODE),
        (C_RFE_TYPE, C_XTAL_K, C_COUNTRY_CODE),
        (N51_RFE_TYPE, N51_XTAL_K, N51_COUNTRY_CODE),
    ] {
        if (rfe, xtal, country) != (0x2ca, 0x2b9, 0x2cb) {
            return TestResult::Fail("AX factory fields differ from original Linux packed types");
        }
    }
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        for valid in [false, true] {
            for power_k in [false, true] {
                let mut source = SourceModel::new(chip);
                source.autoload = if valid { 32 } else { 0 };
                source.extra[0] = if power_k { 0xaa } else { 0xff };
                let mut factory = Factory::default();
                if ready(factory.read(&mut source)) != Some(Ok(())) {
                    return TestResult::Fail("actual factory snapshot refused");
                }
                let id = factory.identity().unwrap();
                if id.chip() != chip
                    || id.cut() != 1
                    || id.mac() != [2, 4, 6, 8, 10, 12]
                    || id.xtal() != 0x33
                    || id.country() != *b"US"
                    || id.fuses().enabled()
                    || id.calibration()
                        != (power::Calibration {
                            rfe_type: 5,
                            valid,
                            power_k_valid: chip == ChipId::Rtl8852B && power_k,
                        })
                    || source.reads != [(0, 1216), (0x5e9, 5)]
                    || factory.logical().unwrap().len()
                        != if chip == ChipId::Rtl8852A { 1536 } else { 2048 }
                {
                    return TestResult::Fail("factory input was defaulted, detached or misdecoded");
                }
                let reads = source.reads.len();
                if ready(factory.read(&mut source)) != Some(Err(Error::Terminal))
                    || source.reads.len() != reads
                {
                    return TestResult::Fail("completed factory snapshot was replayed");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_factory_snapshot_matches_linux_layout_and_actual_controls
);
fn smoke_rtw89_factory_failure_cancel_and_corrected_cut_keep_identity_private() -> TestResult {
    for failed in 0..2 {
        for cancel in [false, true] {
            let mut source = SourceModel::new(ChipId::Rtl8851B);
            if cancel {
                source.pending = Some(failed);
            } else {
                source.fail = Some(failed);
            }
            let mut factory = Factory::default();
            if ready(factory.read(&mut source)) == Some(Ok(()))
                || factory.state() != State::Reading
                || factory.identity().is_some()
                || factory.logical().is_some()
            {
                return TestResult::Fail("uncertain factory transaction published identity");
            }
            let reads = source.reads.len();
            if ready(factory.read(&mut source)) != Some(Err(Error::Terminal))
                || source.reads.len() != reads
            {
                return TestResult::Fail("uncertain factory transaction replayed");
            }
        }
    }
    let mut source = SourceModel::new(ChipId::Rtl8851B);
    source.extra[1] = 0x2f;
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Err(Error::Unsupported))
        || factory.identity().is_some()
    {
        return TestResult::Fail("changed ECV was detached from corrected physical cut");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852B);
    source.extra[3..].fill(0);
    let mut factory = Factory::default();
    if !matches!(
        ready(factory.read(&mut source)),
        Some(Err(Error::Secure(_)))
    ) || factory.identity().is_some()
    {
        return TestResult::Fail("unknown programmed secure fuses became erased defaults");
    }
    let mut source = SourceModel::new(ChipId::Rtl8852B);
    source.autoload = u16::MAX;
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Err(Error::Register(power::Error::Gone)))
        || !source.reads.is_empty()
    {
        return TestResult::Fail("missing factory device used calibration defaults");
    }
    let mut source = SourceModel::new(ChipId::Rtl8922A);
    let mut factory = Factory::default();
    if ready(factory.read(&mut source)) != Some(Err(Error::Unsupported)) || !source.reads.is_empty()
    {
        return TestResult::Fail("BE used AX factory layout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_factory_failure_cancel_and_corrected_cut_keep_identity_private
);
