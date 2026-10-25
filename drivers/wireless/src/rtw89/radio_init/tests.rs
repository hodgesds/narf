use super::super::{
    factory::Source,
    fw::FwError,
    prepared::{self, Files},
};
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
    words: Vec<u32>,
    rfe: u8,
    cut: u8,
    hash: u64,
    count: u32,
    operations: Vec<(u8, u32)>,
    now: u64,
    fail: Option<usize>,
    pending: Option<usize>,
    delays: usize,
    ignore: Option<u32>,
    nctl_stuck: bool,
}
impl Model {
    fn new(seed: u8, rfe: u8, cut: u8) -> Self {
        Self {
            words: vec![u32::from(seed) * 0x01010101; 0x20000 / 4],
            rfe,
            cut,
            hash: 14695981039346656037,
            count: 0,
            operations: Vec::new(),
            now: 0,
            fail: None,
            pending: None,
            delays: 0,
            ignore: None,
            nctl_stuck: false,
        }
    }
    fn octet(&mut self, v: u8) {
        self.hash ^= u64::from(v);
        self.hash = self.hash.wrapping_mul(1099511628211);
    }
    fn values(&mut self, v: &[u32]) {
        self.count += 1;
        for word in v {
            for byte in word.to_le_bytes() {
                self.octet(byte);
            }
        }
    }
    fn access(&mut self, kind: u8, address: u32) -> Result<(), power::Error> {
        let n = self.operations.len();
        self.operations.push((kind, address));
        if self.fail == Some(n) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn clear_trace(&mut self) {
        self.hash = 14695981039346656037;
        self.count = 0;
        self.operations.clear();
        self.delays = 0;
    }
    fn setup(seed: u8, rfe: u8, cut: u8) -> (Self, Qualified, Assets) {
        let mut model = Self::new(seed, rfe, cut);
        let mut factory = Factory::default();
        assert_eq!(ready(factory.read(&mut model)), Some(Ok(())));
        let qualified = Qualified::from_factory(&factory).unwrap();
        let image = prepared::load(&mut FirmwareFiles, ChipId::Rtl8852B, cut).unwrap();
        let assets = Assets::from_prepared(&image).unwrap();
        model.clear_trace();
        (model, qualified, assets)
    }
}
struct FirmwareFiles;
impl Files for FirmwareFiles {
    fn load(&mut self, _: &'static str) -> Result<Vec<u8>, FwError> {
        // Explicit private file fixture; actual image/container parsers still
        // select/validate it, without changing real signed registry admission.
        let mut bytes = vec![0; 52];
        bytes[24..28].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x8000u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&4u32.to_le_bytes());
        Ok(bytes)
    }
}
impl Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Access)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        if a == 0xa {
            Ok(32)
        } else {
            Err(power::Error::Access)
        }
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access(0, a)?;
        if self.nctl_stuck && a == 0x18080 {
            Ok(0)
        } else {
            Ok(self.words[a as usize / 4])
        }
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access(4, a)?;
        self.values(&[4, a, v]);
        if self.ignore != Some(a) {
            self.words[a as usize / 4] = v;
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        let edge = self.delays;
        self.delays += 1;
        self.values(&[8, us as u32, 0]);
        if self.pending == Some(edge) {
            core::future::pending::<()>().await;
        }
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Source for Model {
    fn profile(&self) -> (ChipId, u8) {
        (ChipId::Rtl8852B, self.cut)
    }
    async fn physical(&mut self, start: u16, out: &mut [u8]) -> Result<(), power::Error> {
        out.fill(255);
        match (start, out.len()) {
            (0, 1216) => {
                let mut cursor = 4;
                for (offset, bytes) in [
                    (0x400, [2, 4]),
                    (0x402, [6, 8]),
                    (0x404, [10, 12]),
                    (0x2ca, [self.rfe, b'U']),
                    (0x2cc, [b'S', 255]),
                ] {
                    let block = offset / 8;
                    out[cursor] = (block >> 4) as u8;
                    out[cursor + 1] = ((block & 15) << 4) as u8 | (15 ^ (1 << ((offset % 8) / 2)));
                    out[cursor + 2..cursor + 4].copy_from_slice(&bytes);
                    cursor += 4;
                }
            }
            (0x580, 128) => {}
            _ => return Err(power::Error::Access),
        }
        Ok(())
    }
}
impl Interface for Model {
    async fn radio_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.access(16, address)?;
        self.values(&[16, u32::from(path), address, mask, value]);
        Ok(())
    }
    async fn radio_page(&mut self, path: u8, page: u8, bytes: &[u8]) -> Result<(), Error> {
        self.access(32, u32::from(path) * 4 + u32::from(page))?;
        self.values(&[32, u32::from(path), u32::from(page), bytes.len() as u32]);
        for byte in bytes {
            self.octet(*byte);
        }
        Ok(())
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_b_table_power_reset_rf_upload_and_nctl_match_frozen_references() -> TestResult {
    for &(seed, rfe, cut, count, hash, nctl_count, nctl_hash, unsupported) in CASES {
        let (mut io, qualified, assets) = Model::setup(seed, rfe, cut);
        let mut owner = Init::default();
        if unsupported {
            // SAFETY: actual fixture Factory reports this unsupported RFE;
            // preflight must reject before any possibly partial table write.
            let result = ready(unsafe { owner.prepare(&mut io, qualified, &assets) });
            if !matches!(result, Some(Err(_))) || io.count != 0 || owner.state() != State::Preparing
            {
                return TestResult::Fail(
                    "unsupported Linux RF package reached partial BB/RF writes",
                );
            }
            continue;
        }
        // SAFETY: actual completed Factory and firmware-parser model outputs,
        // complete inert private register memory and no device/DMA producer.
        if ready(unsafe { owner.prepare(&mut io, qualified, &assets) }) != Some(Ok(()))
            || owner.state() != State::TablesLoaded
            || owner.gain().is_none()
            || owner.calibration().is_none()
            || io.count != count
            || io.hash != hash
        {
            return TestResult::Fail(
                "full B BB/power/reset/RF page stream differs from the frozen reference",
            );
        }
        io.clear_trace();
        let program = radio_table::program(assets.table(4).unwrap(), rfe, cut).unwrap();
        if ready(nctl(&mut io, &program)) != Some(Ok(()))
            || io.count != nctl_count
            || io.hash != nctl_hash
        {
            return TestResult::Fail(
                "B NCTL pre-init/table stream differs from the frozen reference",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_table_power_reset_rf_upload_and_nctl_match_frozen_references
);
fn smoke_rtw89_b_table_failures_cancel_and_ignored_critical_writes_never_replay() -> TestResult {
    let (mut io, q, assets) = Model::setup(0, 1, 0);
    let mut owner = Init::default();
    // SAFETY: same complete exclusive inert factory/firmware/register fixture.
    if ready(unsafe { owner.prepare(&mut io, q, &assets) }) != Some(Ok(())) {
        return TestResult::Fail("radio table failure baseline");
    }
    let mut failures = vec![0, io.operations.len() - 1];
    for (i, &(kind, a)) in io.operations.iter().enumerate() {
        if kind == 32
            || [
                0xd248, 0xd220, 0xd240, 0xd288, 0xd28c, 0xd290, 0x10704, 0x11200, 0x13200,
            ]
            .contains(&a)
        {
            failures.push(i);
        }
    }
    if let Some(i) = io.operations.iter().position(|v| v.0 == 16) {
        failures.push(i);
    }
    failures.sort_unstable();
    failures.dedup();
    for failure in failures {
        let (mut io, q, assets) = Model::setup(0, 1, 0);
        io.fail = Some(failure);
        let mut owner = Init::default();
        // SAFETY: same inert exact-profile fixture, with an injected bus error.
        let result = ready(unsafe { owner.prepare(&mut io, q, &assets) });
        if !matches!(result, Some(Err(_)))
            || owner.state() != State::Preparing
            || owner.gain().is_some()
        {
            return TestResult::Fail("radio table failure published gain/readiness");
        }
        let before = io.operations.len();
        // SAFETY: failed private owner must reject before any further I/O.
        if ready(unsafe { owner.prepare(&mut io, q, &assets) }) != Some(Err(Error::Terminal))
            || io.operations.len() != before
        {
            return TestResult::Fail("failed radio table owner replayed writes");
        }
    }
    for pending in 0..io.delays {
        let (mut io, q, assets) = Model::setup(0, 1, 0);
        io.pending = Some(pending);
        let mut owner = Init::default();
        // SAFETY: same retained inert model; cancellation must leave Preparing.
        if ready(unsafe { owner.prepare(&mut io, q, &assets) }).is_some()
            || owner.state() != State::Preparing
            || owner.gain().is_some()
        {
            return TestResult::Fail("radio cancellation published completed table state");
        }
        let before = io.operations.len();
        // SAFETY: cancelled private owner remains closed before I/O.
        if ready(unsafe { owner.prepare(&mut io, q, &assets) }) != Some(Err(Error::Terminal))
            || io.operations.len() != before
        {
            return TestResult::Fail("cancelled radio table owner replayed");
        }
    }
    for a in [0xd248, 0xd220, 0xd240, 0xd288, 0xd290, 0x10704] {
        let (mut io, q, assets) = Model::setup(0, 1, 0);
        io.ignore = Some(a);
        let mut owner = Init::default();
        // SAFETY: same private inert model; ignored writes must fail readback.
        let result = ready(unsafe { owner.prepare(&mut io, q, &assets) });
        if !matches!(result, Some(Err(_))) || owner.state() == State::TablesLoaded {
            return TestResult::Fail("ignored power/reset write became table readiness");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_table_failures_cancel_and_ignored_critical_writes_never_replay
);
fn smoke_rtw89_b_radio_bad_tables_and_nctl_deadline_fail_closed() -> TestResult {
    if validate_bb(&[Pair(0x10000, 0)]).is_ok()
        || validate_bb(&[Pair(0x101, 0)]).is_ok()
        || rf_pages(&[Pair(0x20055, 0)]).is_ok()
        || rf_pages(&vec![Pair(0x10055, 0); 1501]).is_ok()
    {
        return TestResult::Fail("invalid PHY aperture/RF page program accepted");
    }
    let mut io = Model::new(0, 1, 0);
    io.nctl_stuck = true;
    if ready(nctl(&mut io, &[Pair(0x8040, 0x12345)]))
        != Some(Err(Error::Register(power::Error::Timeout)))
        || io.now < 1000
        || io.now > 1012
        || io.words[0x18040 / 4] != 0
    {
        return TestResult::Fail("NCTL timeout continued into calibration table writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_radio_bad_tables_and_nctl_deadline_fail_closed
);

include!("control_golden.rs");
fn smoke_rtw89_b_bb_hardware_controls_match_frozen_references_and_retain_bases() -> TestResult {
    for &(seed, count, hash, bases) in CONTROLS {
        let mut io = Model::new(seed, 1, 1);
        if controls(&mut io) != Ok(bases) || io.count != count || io.hash != hash {
            return TestResult::Fail("B bb_sethw/MACID/RPL differs from the frozen reference");
        }
        let operations = io.operations.len();
        for failed in 0..operations {
            let mut io = Model::new(seed, 1, 1);
            io.fail = Some(failed);
            if controls(&mut io).is_ok() {
                return TestResult::Fail("partial BB control read/write returned bases");
            }
        }
    }
    for address in [0x10d7c, 0x12d7c, 0xd36c, 0xd568] {
        let mut io = Model::new(0xa5, 1, 1);
        io.words[0x10d7c / 4] |= 2;
        io.words[0x12d7c / 4] |= 2;
        io.ignore = Some(address);
        if controls(&mut io).is_ok() {
            return TestResult::Fail("ignored BB control/limit write returned readiness");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_bb_hardware_controls_match_frozen_references_and_retain_bases
);
