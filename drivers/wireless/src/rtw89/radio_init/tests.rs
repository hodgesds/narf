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
    chip: ChipId,
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
            chip: ChipId::Rtl8852B,
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
        (self.chip, self.cut)
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
            (0x590, 0x60) if self.chip == ChipId::Rtl8852C => {}
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
/// Minimal MFW container carrying the shipped RTL8852C element order.
fn c_container(rf_a: u32, rf_b: u32) -> Vec<u8> {
    let mut bytes = vec![0; 48];
    bytes[0] = 255;
    bytes[1] = 1;
    bytes[20..24].copy_from_slice(&32u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&16u32.to_le_bytes());
    for (id, idx, address, value) in [
        (2u32, 0u8, 0x0704u32, 0x601e_0100u32),
        (3, 0, 0x0000_0000, 0x0102_0304),
        (4, 1, rf_a, 0x11),
        (5, 0, rf_b, 0x22),
        (8, 0, 0x0c60, 0),
    ] {
        let start = bytes.len();
        bytes.resize(start + 32, 0);
        bytes[start..start + 4].copy_from_slice(&id.to_le_bytes());
        bytes[start + 4..start + 8].copy_from_slice(&8u32.to_le_bytes());
        bytes[start + 24] = idx;
        bytes.extend_from_slice(&address.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
        // fw.c: the next element starts at ALIGN(offset,
        // RTW89_FW_ELEMENT_ALIGN = 16).
        bytes.resize(bytes.len().div_ceil(16) * 16, 0);
    }
    bytes
}
fn smoke_rtw89_c_table_power_reset_and_rf_order_follow_rtw8852c() -> TestResult {
    let mut model = Model::new(0x5a, 1, 1);
    model.chip = ChipId::Rtl8852C;
    let mut factory = Factory::default();
    if ready(factory.read(&mut model)) != Some(Ok(())) {
        return TestResult::Fail("C factory snapshot failed");
    }
    if Qualified::from_factory(&factory).is_some() {
        return TestResult::Fail("B qualification accepted a C factory");
    }
    let Some(qualified) = Qualified::from_factory_c(&factory) else {
        return TestResult::Fail("C qualification refused an actual C factory");
    };
    let assets = Assets::parse_for(ChipId::Rtl8852C, &c_container(0x10005, 0x10006)).unwrap();
    model.clear_trace();
    let mut init = Init::default();
    // SAFETY: private model Interface; no hardware.
    if ready(unsafe { init.prepare(&mut model, qualified, &assets) }) != Some(Ok(()))
        || init.state() != State::TablesLoaded
        || init.calibration().is_some()
        || init.calibration_c().is_none()
    {
        return TestResult::Fail("C table preparation failed or published B calibration");
    }
    // Linux `rf_table = {radiob, radioa}`: path B (1) is written and paged
    // before path A (0), each with its own path.
    let rf: Vec<(u8, u32)> = model
        .operations
        .iter()
        .copied()
        .filter(|(kind, _)| *kind == 16 || *kind == 32)
        .collect();
    if rf != [(16, 0x10006), (32, 4), (16, 0x10005), (32, 0)] {
        return TestResult::Fail("C RF tables were not uploaded in rtw8852c rf_table order");
    }
    for (address, value) in [
        (0x10704, 0x601e_0100 | 2),
        (0xd248, 0x0776_3333),
        (0xd220, 0x01eb_f000),
        (0xd240, 0x0002_f8ff),
        (0xd28c, 0),
        (0xd290, 0xf4f4_f4f4),
        (0xd908, 0),
        (0xd938, 0x0001_0100),
        (0xd93c, 0x0500_d500),
        (0xd94c, 0x0022_0000),
        (0xd950, 0x0003_0000),
        (0xd95c, 0),
    ] {
        if model.words[address / 4] != value {
            return TestResult::Fail(
                "C txpwr unit / TSSI ctrl / BB reset state differs from Linux",
            );
        }
    }
    // C never touches B's TSSI-tracking pause or UL_TB enable bit.
    if model
        .operations
        .iter()
        .any(|(kind, a)| *kind == 4 && matches!(*a, 0x158dc | 0x15818 | 0x178dc | 0x17818 | 0xd288))
    {
        return TestResult::Fail("C reset used B-only registers");
    }
    // Chip mismatch between qualification and assets fails before any write.
    let (mut b_model, _, b_assets) = Model::setup(0x5a, 1, 1);
    b_model.clear_trace();
    let mut init = Init::default();
    // SAFETY: private model Interface; no hardware.
    if ready(unsafe { init.prepare(&mut b_model, qualified, &b_assets) })
        != Some(Err(Error::Profile))
        || !b_model.operations.is_empty()
    {
        return TestResult::Fail("C qualification ran B assets");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_table_power_reset_and_rf_order_follow_rtw8852c
);
fn smoke_rtw89_c_bb_sethw_gpio_and_nctl_follow_rtw8852c() -> TestResult {
    let mut io = Model::new(0xa5, 1, 1);
    io.words[0x14df0 / 4] = 0x1234_56f6;
    io.words[0x16df0 / 4] = 0x0000_0007;
    if controls_c(&mut io) != Ok([-10, 7]) {
        return TestResult::Fail("C bb_sethw did not return R_RPL_BIAS_COMP{,1} [7:0]");
    }
    // 0xa5a5a5a5 seed: TRSW_A set, TRSW_X/SO_A2 clear, [31:16] = 0xa9a9,
    // untouched [15:8]/bit 4/bit 3/bit 0 kept.
    for base in [0x15800, 0x17800] {
        if io.words[(base | 0x68) / 4] != 0xa9a9_a503
            || io.words[(base | 0x80) / 4] != 0x7777_7777
            || io.words[(base | 0x84) / 4] != 0x7777_7777
            || io.words[(base | 0x94) / 4] != 0xa508_0400
        {
            return TestResult::Fail("C bb_gpio_init TRSW/RFM state differs from Linux");
        }
    }
    if io.words[0x10a10 / 4] != 0xa5a5_a5a5
        || io.words[0x12a10 / 4] != 0xa5a5_a5a5
        || io.words[0x10334 / 4] != u32::MAX
        || io.words[0x10338 / 4] != 0
        || io.words[0xd36c / 4] != 0
        || io.words[0xd568 / 4] != 0
        || io.words[0xd56c / 4] != 0xa5a5_a5a5
    {
        return TestResult::Fail("C EVM report/RFE/MACID limit state differs from Linux");
    }
    // B-only bb_sethw registers are never touched.
    if io
        .operations
        .iter()
        .any(|(kind, a)| *kind == 4 && matches!(*a, 0x10d7c | 0x12d7c))
    {
        return TestResult::Fail("C bb_sethw wrote B-only registers");
    }
    for address in [0x10a10, 0x15868, 0x17894, 0x10340, 0xd400] {
        let mut io = Model::new(0x5a, 1, 1);
        io.ignore = Some(address);
        if controls_c(&mut io).is_ok() {
            return TestResult::Fail("ignored C bb_sethw write returned readiness");
        }
    }
    // C NCTL pre-init skips the RTL8852B second IOQ write.
    let mut io = Model::new(0, 1, 1);
    io.words[0x18080 / 4] = 4;
    if ready(nctl_c(&mut io, &[Pair(0x8040, 0x12345)])) != Some(Ok(()))
        || io.words[0x10c60 / 4] != 3
        || io.words[0x18040 / 4] != 0x12345
        || io
            .operations
            .iter()
            .filter(|(kind, a)| *kind == 4 && *a == 0x10c60)
            .count()
            != 1
    {
        return TestResult::Fail("C NCTL pre-init/table differs from rtw89_phy_preinit_rf_nctl_ax");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_bb_sethw_gpio_and_nctl_follow_rtw8852c
);
fn n51_container(rf_a: u32) -> Vec<u8> {
    let mut bytes = vec![0; 48];
    bytes[0] = 255;
    bytes[1] = 1;
    bytes[20..24].copy_from_slice(&32u32.to_le_bytes());
    bytes[24..28].copy_from_slice(&16u32.to_le_bytes());
    // The shipped rtw8851b_fw-1.bin PHY set: BB, GAIN, RADIO_A idx0, NCTL.
    for (id, address, value) in [
        (2u32, 0x0704u32, 0x601e_0100u32),
        (3, 0x0000_0000, 0x0102_0304),
        (4, rf_a, 0x11),
        (8, 0x0c60, 0),
    ] {
        let start = bytes.len();
        bytes.resize(start + 32, 0);
        bytes[start..start + 4].copy_from_slice(&id.to_le_bytes());
        bytes[start + 4..start + 8].copy_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(&address.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
        // fw.c: the next element starts at ALIGN(offset,
        // RTW89_FW_ELEMENT_ALIGN = 16).
        bytes.resize(bytes.len().div_ceil(16) * 16, 0);
    }
    bytes
}
fn smoke_rtw89_n51_table_power_reset_and_single_rf_path_follow_rtw8851b() -> TestResult {
    let mut model = Model::new(0x5a, 1, 1);
    model.chip = ChipId::Rtl8851B;
    let mut factory = Factory::default();
    if ready(factory.read(&mut model)) != Some(Ok(())) {
        return TestResult::Fail("8851B factory snapshot failed");
    }
    if Qualified::from_factory(&factory).is_some() || Qualified::from_factory_c(&factory).is_some()
    {
        return TestResult::Fail("B/C qualification accepted an 8851B factory");
    }
    let Some(qualified) = Qualified::from_factory_51(&factory) else {
        return TestResult::Fail("8851B qualification refused an actual 8851B factory");
    };
    let assets = Assets::parse_for(ChipId::Rtl8851B, &n51_container(0x10005)).unwrap();
    model.clear_trace();
    let mut init = Init::default();
    // SAFETY: private model Interface; no hardware.
    if ready(unsafe { init.prepare(&mut model, qualified, &assets) }) != Some(Ok(()))
        || init.state() != State::TablesLoaded
        || init.calibration().is_some()
        || init.calibration_c().is_some()
        || init.calibration_51().is_none()
    {
        return TestResult::Fail("8851B table preparation failed or published a B/C calibration");
    }
    // `rf_table = {radioa}`: only path A is written and paged.
    let rf: Vec<(u8, u32)> = model
        .operations
        .iter()
        .copied()
        .filter(|(kind, _)| *kind == 16 || *kind == 32)
        .collect();
    if rf != [(16, 0x10005), (32, 0)] {
        return TestResult::Fail("8851B RF upload was not the single path-A table");
    }
    // rtw8851b_init_txpwr_unit + rtw8851b_bb_reset final state: TXPW_RSTB
    // MANON|TSSI = 3, TSSI_TRK EN clear, S0 HW-SI trigger released.
    for (address, value, mask) in [
        (0x10704usize, 0x601e_0100 | 2, u32::MAX),
        (0xd248, 0x0776_3333, u32::MAX),
        (0xd220, 0x01eb_f000, u32::MAX),
        (0xd240, 0x0002_f8ff, u32::MAX),
        (0xd288, 1 << 31, 1 << 31),
        (0xd28c, 0, 31),
        (0xd290, 29, 31),
        (0x158dc, 0xc000_0000, 0xc000_0000),
        (0x15818, 0, 1 << 30),
        (0x11200, 0, 0x7000_0000),
    ] {
        if model.words[address / 4] & mask != value {
            return TestResult::Fail("8851B txpwr unit / BB reset state differs from Linux");
        }
    }
    // One path: no S1 HW-SI trigger and no path-B TSSI registers.
    if model
        .operations
        .iter()
        .any(|(kind, a)| *kind == 4 && matches!(*a, 0x13200 | 0x178dc | 0x17818))
    {
        return TestResult::Fail("8851B reset touched path-B registers");
    }
    // B assets under an 8851B qualification fail before any write.
    let (mut b_model, _, b_assets) = Model::setup(0x5a, 1, 1);
    b_model.clear_trace();
    let mut init = Init::default();
    // SAFETY: private model Interface; no hardware.
    if ready(unsafe { init.prepare(&mut b_model, qualified, &b_assets) })
        != Some(Err(Error::Profile))
        || !b_model.operations.is_empty()
    {
        return TestResult::Fail("8851B qualification ran B assets");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_table_power_reset_and_single_rf_path_follow_rtw8851b
);
fn smoke_rtw89_n51_bb_sethw_gpio_and_nctl_post_follow_rtw8851b() -> TestResult {
    let mut io = Model::new(0xa5, 1, 1);
    io.words[0x149b0 / 4] = 0x1234_56f6;
    io.words[0x14a00 / 4] = 0x0000_0007;
    if controls_51(&mut io) != Ok([-10, 7]) {
        return TestResult::Fail("8851B bb_sethw did not return R_P0_RPL1/R_P1_RPL1 [7:0]");
    }
    // 0xa5a5a5a5 seed: TRSW_A set, TRSW_X/SO_A2 clear, [31:16] = 0xa9a9.
    if io.words[0x15868 / 4] != 0xa9a9_a503
        || io.words[0x15880 / 4] != 0x7777_7777
        || io.words[0x15884 / 4] != 0x7777_7777
        || io.words[0x10334 / 4] != u32::MAX
        || io.words[0x10338 / 4] != 0
        || io.words[0x1033c / 4] != 0
        || io.words[0x10340 / 4] != 0
        || io.words[0x10d7c / 4] != 0xa5a5_a5a5 & !2
        || io.words[0xd260 / 4] != (0xa5a5_a5a5 & !0x20) | 0x40
        || io.words[0xd36c / 4] != 0
        || io.words[0xd568 / 4] != 0
        || io.words[0xd56c / 4] != 0xa5a5_a5a5
    {
        return TestResult::Fail("8851B bb_sethw GPIO/NTX/MACID state differs from Linux");
    }
    // One path: no path-B GPIO, sounding or C EVM-report registers.
    if io.operations.iter().any(|(kind, a)| {
        *kind == 4
            && matches!(
                *a,
                0x12d7c | 0x17868 | 0x17880 | 0x17884 | 0x10a10 | 0x12a10
            )
    }) {
        return TestResult::Fail("8851B bb_sethw wrote path-B or C-only registers");
    }
    // Seeds chosen so each ignored write leaves a visibly wrong field.
    for (address, seed) in [
        (0x10d7c, 0x5a),
        (0x15868, 0x5a),
        (0x10340, 0x5a),
        (0xd400, 0x5a),
        (0xd260, 0xa5),
    ] {
        let mut io = Model::new(seed, 1, 1);
        io.ignore = Some(address);
        if controls_51(&mut io).is_ok() {
            return TestResult::Fail("ignored 8851B bb_sethw write returned readiness");
        }
    }
    // NCTL: no R_P1_PATH_RST and no second IOQ write, then the post table.
    let mut io = Model::new(0, 1, 1);
    io.words[0x18080 / 4] = 4;
    if ready(nctl_51(&mut io, &[Pair(0x8040, 0x12345)])) != Some(Ok(()))
        || io.words[0x18040 / 4] != 0x12345
        || io.words[0x10c60 / 4] != 3
        || io.words[0x15864 / 4] != 0x1800_0000
        || io.words[0x17864 / 4] != 0x1800_0000
        || io.words[0x1030c / 4] != 0x1300_0000
        || io.words[0x1032c / 4] != 0x0041_0000
        || io.words[0x112b8 / 4] != 0x1000_0000
        || io.words[0x12008 / 4] != 0x000f_ffff
        || io.words[0x158ac / 4] != 0x0800_0000
        || io.words[0x178ac / 4] != 0x0800_0000
        || io.words[0x10730 / 4] != 0x3800
        || io.words[0x12730 / 4] != 0x3800
        || io.words[0x10c7c / 4] != 0x0020_0000
    {
        return TestResult::Fail("8851B NCTL table/post defs differ from rtw8851b_nctl_post_defs");
    }
    let preinit_p1 = io
        .operations
        .iter()
        .position(|(kind, a)| *kind == 4 && *a == 0x178ac);
    let table = io
        .operations
        .iter()
        .position(|(kind, a)| *kind == 4 && *a == 0x18040);
    if preinit_p1.zip(table).is_none_or(|(p1, t)| p1 < t)
        || io
            .operations
            .iter()
            .take_while(|(kind, a)| !(*kind == 4 && *a == 0x18040))
            .filter(|(kind, a)| *kind == 4 && *a == 0x10c60)
            .count()
            != 1
    {
        return TestResult::Fail("8851B NCTL pre-init wrote R_P1_PATH_RST or a second IOQ");
    }
    let mut io = Model::new(0, 1, 1);
    io.words[0x18080 / 4] = 4;
    io.ignore = Some(0x12008);
    if ready(nctl_51(&mut io, &[Pair(0x8040, 0x12345)])).is_none_or(|r| r.is_ok()) {
        return TestResult::Fail("ignored 8851B NCTL post write returned readiness");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_bb_sethw_gpio_and_nctl_post_follow_rtw8851b
);
