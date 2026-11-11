use super::super::super::operating_channel_c::Width;
use super::super::super::txpower_8922a::{PathEfuse, TssiProfile};
use super::super::Kind;
use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// BB word + RF register + H2C/report transport model for the BE
/// channel owner. RF 0x00 (RR_MOD) returns RX mode after a programmed
/// number of polls; the report queue answers each offload in order.
struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    rx_mode_polls: [u8; 2],
    h2c: Vec<(u8, u8, u8, Vec<u8>)>,
    reports: VecDeque<be_rfk::Report>,
    timeouts: Vec<u64>,
    coex: Vec<bool>,
    paused: bool,
    resumed: bool,
    now: u64,
}
impl Model {
    fn new(reports: Vec<be_rfk::Report>) -> Self {
        Self {
            // MAC + the BE PHY window (0x20000 + CR, e.g. the TSSI code
            // registers at 0x2ee10 / 0x2ef10).
            words: vec![0; 0x30000 / 4],
            rf: core::array::from_fn(|_| vec![0; 0x200]),
            rx_mode_polls: [0; 2],
            h2c: Vec::new(),
            reports: reports.into(),
            timeouts: Vec::new(),
            coex: Vec::new(),
            paused: false,
            resumed: false,
            now: 0,
        }
    }
    fn ok(version: u8) -> be_rfk::Report {
        be_rfk::Report {
            state: be_rfk::ReportState::Ok,
            version,
        }
    }
    fn tssi_inputs<'a>(
        profile: &'a TssiProfile,
        tracking: &'a super::super::c_tssi::Tracking,
    ) -> Inputs<'a> {
        Inputs {
            profile,
            trim: [[0; 8]; 2],
            trim_6g: [[0; 16]; 2],
            tracking,
            rfe_type: 0x5a,
            cv: 0,
        }
    }
}
impl power::Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        Ok(self.words[a as usize / 4])
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.words[a as usize / 4] = v;
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        // RR_MOD (0x00) polls: TX mode (2) while polls remain, RX (0).
        // u8::MAX means never (the wait must time out).
        if address == 0 && mask == 0xf0000 {
            let p = usize::from(path);
            if self.rx_mode_polls[p] == u8::MAX {
                return Ok(2);
            }
            if self.rx_mode_polls[p] > 0 {
                self.rx_mode_polls[p] -= 1;
                return Ok(2);
            }
            return Ok(0);
        }
        let value = self.rf[usize::from(path)][address as usize];
        Ok((value & mask) >> mask.trailing_zeros())
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        let slot = &mut self.rf[usize::from(path)][address as usize];
        *slot = (*slot & !mask) | ((value << mask.trailing_zeros()) & mask);
        Ok(())
    }
    async fn begin(&mut self, _: Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn end(&mut self, _: Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.paused = true;
        Ok(0)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        self.resumed = true;
        Ok(())
    }
    async fn h2c(&mut self, cat: u8, class: u8, func: u8, payload: &[u8]) -> Result<(), Error> {
        self.h2c.push((cat, class, func, payload.to_vec()));
        Ok(())
    }
    async fn await_rfk_report(&mut self, timeout_ms: u64) -> Result<be_rfk::Report, Error> {
        self.timeouts.push(timeout_ms);
        self.reports
            .pop_front()
            .ok_or(Error::Register(power::Error::Timeout))
    }
    async fn coex_rfk(&mut self, start: bool) -> Result<(), Error> {
        self.coex.push(start);
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

fn tracking() -> super::super::c_tssi::Tracking {
    let mut element = [5u8; 1088];
    element[0] = 0xff;
    element[1] = 0xff;
    element[2] = 0;
    element[3] = 0;
    super::super::c_tssi::Tracking::parse(&element).expect("tracking element")
}

fn tssi_profile() -> TssiProfile {
    let a = PathEfuse {
        therm: 0x20,
        cck_tssi: [10, 20, 30, 40, 50, 60],
        bw40_tssi: [1, 2, 3, 4, 5],
        bw40_1s_tssi_5g: [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
        bw40_1s_tssi_6g: [
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
            42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
        ],
    };
    let b = PathEfuse {
        therm: 0x20,
        cck_tssi: [110, 120, 130, 140, 150, 160],
        bw40_tssi: [101, 102, 103, 104, 105],
        bw40_1s_tssi_5g: [
            106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
        ],
        bw40_1s_tssi_6g: [
            120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
            137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
        ],
    };
    TssiProfile::parse([a, b])
}

fn smoke_rtw89_be_channel_rfk_and_track() -> TestResult {
    let tracking = tracking();
    let profile = tssi_profile();
    let inputs = Model::tssi_inputs(&profile, &tracking);
    // 5GHz 80MHz primary 36 (center 42).
    let Some(wide) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    let channel = Channel::default();
    if channel.state() != State::New
        || channel.calibrated().is_some()
        || channel.conn_rfk()
        || channel.tracks() != 0
    {
        return TestResult::Fail("fresh BE channel owner is not New");
    }
    // Track before calibration is terminal.
    let mut channel = Channel::default();
    let mut io = Model::new(vec![]);
    // SAFETY: private inert register/RF model; no hardware.
    let track = unsafe { channel.track(&mut io, false) };
    if ready(track) != Some(Err(Error::Terminal)) {
        return TestResult::Fail("BE track runs before calibration");
    }
    // Band change (TSSI SCAN) from New: one TSSI H2C, scan mode, no
    // state change.
    let mut io = Model::new(vec![Model::ok(1)]);
    // SAFETY: private inert register/RF model; no hardware.
    let band = unsafe { channel.band_changed(&mut io, wide, &inputs) };
    if ready(band) != Some(Ok(())) {
        return TestResult::Fail("BE band_changed failed on a ready model");
    }
    if io.h2c.len() != 1
        || io.h2c[0].0 != 2
        || io.h2c[0].1 != 0xB
        || io.h2c[0].2 != 0x0
        || io.h2c[0].3.len() != 300
        || io.h2c[0].3[298] != 1
        || io.timeouts != vec![TSSI_SCAN_MS]
        || channel.record(ReportKind::Tssi) != Some(Model::ok(1))
        || channel.state() != State::New
    {
        return TestResult::Fail("BE band_changed does not send the TSSI SCAN offload");
    }
    // Full channel RFK: RX mode after one TX poll per path, then the
    // six offloads in Linux order with Linux timeouts.
    let mut io = Model::new(vec![
        Model::ok(1),
        Model::ok(2),
        Model::ok(3),
        Model::ok(4),
        Model::ok(5),
        Model::ok(6),
    ]);
    io.rx_mode_polls = [1, 1];
    // SAFETY: private inert register/RF model; no hardware.
    let rfk = unsafe { channel.rfk_channel(&mut io, wide, &inputs, MLO_NOT_SUPPORT) };
    if ready(rfk) != Some(Ok(())) {
        return TestResult::Fail("BE rfk_channel failed on a ready model");
    }
    let funcs: Vec<u8> = io.h2c.iter().map(|c| c.2).collect();
    if funcs != vec![0x8, 0x4, 0x1, 0x0, 0x3, 0x6]
        || io.timeouts != vec![PRE_NTFY_MS, TXGAPK_MS, IQK_MS, TSSI_MS, DPK_MS, RXDCK_MS]
        || !io.h2c.iter().all(|c| c.0 == 2 && c.1 == 0xB)
        || io.coex != vec![true, false]
        || !io.paused
        || !io.resumed
        || channel.state() != State::Calibrated
        || channel.calibrated() != Some(wide)
        || channel.conn_rfk()
    {
        return TestResult::Fail("BE rfk_channel order/timeouts/notify differ from rtw8922a");
    }
    // Spot-check the offload bodies: pre_ntfy V3, IQK, TSSI, RXDCK.
    if io.h2c[0].3 != vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        || io.h2c[2].3 != vec![8, 0, 0, 3, 1, 2, 42, 0]
        || io.h2c[3].3.len() != 300
        || io.h2c[3].3[3] != 42
        || io.h2c[3].3[298] != 0
        || io.h2c[4].3 != vec![8, 0, 1, 3, 1, 2, 42, 0]
        || io.h2c[5].3 != vec![9, 0, 0, 3, 1, 2, 42, 0, 1]
    {
        return TestResult::Fail("BE rfk_channel offload bodies differ from fw.c");
    }
    for (kind, version) in [
        (ReportKind::PreNtfy, 1),
        (ReportKind::Txgapk, 2),
        (ReportKind::Iqk, 3),
        (ReportKind::Tssi, 4),
        (ReportKind::Dpk, 5),
        (ReportKind::RxDck, 6),
    ] {
        if channel.record(kind) != Some(Model::ok(version)) {
            return TestResult::Fail("BE rfk_channel does not record every report");
        }
    }
    // Periodic track: MCC mode skips with no access; a live tick
    // snapshots the TSSI codes and counts.
    let mut io = Model::new(vec![]);
    // SAFETY: private inert register/RF model; no hardware.
    let track_mcc = unsafe { channel.track(&mut io, true) };
    if ready(track_mcc) != Some(Ok(false)) || channel.tracks() != 0 {
        return TestResult::Fail("BE track does not skip MCC mode");
    }
    io.words[0x2ee10 / 4] = 0x0005_0000;
    io.words[0x2ef10 / 4] = 0x0002_4000;
    // SAFETY: private inert register/RF model; no hardware.
    let track_live = unsafe { channel.track(&mut io, false) };
    if ready(track_live) != Some(Ok(true)) || channel.tracks() != 1 {
        return TestResult::Fail("BE track failed on a calibrated channel");
    }
    if channel.tssi_codes()[0] != [0x140, 0x90] {
        return TestResult::Fail("BE track TSSI codes differ from rtw89_core_rfk_tssi_record");
    }
    // A failed DPK report fails closed, records the failure, and
    // leaves the owner terminal.
    let mut channel = Channel::default();
    let mut io = Model::new(vec![
        Model::ok(1),
        Model::ok(2),
        Model::ok(3),
        Model::ok(4),
        be_rfk::Report {
            state: be_rfk::ReportState::Fail,
            version: 0,
        },
    ]);
    // SAFETY: private inert register/RF model; no hardware.
    let rfk_fail = unsafe { channel.rfk_channel(&mut io, wide, &inputs, MLO_NOT_SUPPORT) };
    if ready(rfk_fail) != Some(Err(Error::Report))
        || channel.state() != State::Busy
        || channel.calibrated().is_some()
        || channel.record(ReportKind::Dpk)
            != Some(be_rfk::Report {
                state: be_rfk::ReportState::Fail,
                version: 0,
            })
        || io.h2c.len() != 5
    {
        return TestResult::Fail("BE rfk_channel does not fail closed on a failed DPK report");
    }
    // RX-mode timeout: the wait gives up after the 5000 us budget.
    let mut channel = Channel::default();
    let mut io = Model::new(vec![]);
    io.rx_mode_polls = [u8::MAX; 2];
    // SAFETY: private inert register/RF model; no hardware.
    let rfk_timeout = unsafe { channel.rfk_channel(&mut io, wide, &inputs, MLO_NOT_SUPPORT) };
    if ready(rfk_timeout) != Some(Err(Error::Register(power::Error::Timeout)))
        || channel.state() != State::Busy
        || !io.h2c.is_empty()
    {
        return TestResult::Fail("BE rfk_channel does not time out waiting for RX mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_channel_rfk_and_track
);
