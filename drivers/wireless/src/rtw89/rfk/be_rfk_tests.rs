use super::super::super::power;
use super::super::Kind;
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Minimal transport model: records H2C sends, answers each report
/// wait from a canned queue (empty queue = transport timeout).
struct Model {
    h2c: Vec<(u8, u8, u8, Vec<u8>)>,
    reports: Vec<Report>,
    timeouts: Vec<u64>,
    now: u64,
}
impl Model {
    fn new(reports: Vec<Report>) -> Self {
        Self {
            h2c: Vec::new(),
            reports,
            timeouts: Vec::new(),
            now: 0,
        }
    }
    fn ok(version: u8) -> Report {
        Report {
            state: ReportState::Ok,
            version,
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
    fn read32(&mut self, _: u32) -> Result<u32, power::Error> {
        Err(power::Error::Access)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), power::Error> {
        Err(power::Error::Access)
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
    async fn rf_read(&mut self, _: u8, _: u32, _: u32) -> Result<u32, Error> {
        Err(Error::Terminal)
    }
    async fn rf_write(&mut self, _: u8, _: u32, _: u32, _: u32) -> Result<(), Error> {
        Err(Error::Terminal)
    }
    async fn begin(&mut self, _: Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn end(&mut self, _: Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        Ok(0)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        Ok(())
    }
    async fn h2c(&mut self, cat: u8, class: u8, func: u8, payload: &[u8]) -> Result<(), Error> {
        self.h2c.push((cat, class, func, payload.to_vec()));
        Ok(())
    }
    async fn await_rfk_report(&mut self, timeout_ms: u64) -> Result<Report, Error> {
        self.timeouts.push(timeout_ms);
        if self.reports.is_empty() {
            return Err(power::Error::Timeout.into());
        }
        Ok(self.reports.remove(0))
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// One C2H RFK report frame: header word 0 (category 2, class 0x9,
/// function 0), word 1 (length 10), state, version.
fn report_frame(state: u8, version: u8) -> [u8; 10] {
    // func 0 (`RTW89_PHY_C2H_RFK_REPORT` STATE).
    let w0 = 2u32 | (0x9 << 2);
    let mut out = [0u8; 10];
    out[0..4].copy_from_slice(&w0.to_le_bytes());
    out[4..8].copy_from_slice(&10u32.to_le_bytes());
    out[8] = state;
    out[9] = version;
    out
}

fn smoke_rtw89_be_rfk_offload_bodies_and_report_wait() -> TestResult {
    // H2C bodies are byte-exact against fw.c/fw.h.
    if pre_ntfy_body(0, 1, false) != [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
        return TestResult::Fail("BE pre_ntfy V3 body differs from rtw89_fw_h2c_rf_pre_ntfy");
    }
    if iqk_body(0, RF_AB, 1, 2, 42, 0) != [8, 0, 0, 3, 1, 2, 42, 0] {
        return TestResult::Fail("BE IQK body differs from rtw89_fw_h2c_rf_iqk");
    }
    if iqk_v0_body(0, false) != [0u8; 8] || iqk_v0_body(1, true) != [1, 0, 0, 0, 1, 0, 0, 0] {
        return TestResult::Fail("BE IQK V0 body differs from rtw89_h2c_rf_iqk_v0");
    }
    if dpk_body(0, 1, 2, 42, false) != [8, 0, 1, 3, 1, 2, 42, 0] {
        return TestResult::Fail("BE DPK body differs from rtw89_fw_h2c_rf_dpk");
    }
    if txgapk_body(0, 1, 2, 42, 0) != [8, 2, 0, 3, 1, 2, 42, 0] {
        return TestResult::Fail("BE TXGAPK body differs from rtw89_fw_h2c_rf_txgapk");
    }
    if dack_body(0) != [3, 0, 0] {
        return TestResult::Fail("BE DACK body differs from rtw89_fw_h2c_rf_dack");
    }
    if rxdck_body(0, 1, 2, 42, false, true) != [9, 0, 0, 3, 1, 2, 42, 0, 1] {
        return TestResult::Fail("BE RXDCK body differs from rtw89_fw_h2c_rf_rxdck");
    }
    if rxdck_v0_body(0, 1, 2, 42, false) != [8, 0, 0, 3, 1, 2, 42, 0] {
        return TestResult::Fail("BE RXDCK V0 body differs from rtw89_h2c_rf_rxdck_v0");
    }
    // Report kinds carry their Linux H2C functions and names.
    if ReportKind::PreNtfy.func() != FUNC_PRE_NOTIFY
        || ReportKind::Tssi.func() != FUNC_TSSI_OFFLOAD
        || ReportKind::Iqk.func() != FUNC_IQK_OFFLOAD
        || ReportKind::Dpk.func() != FUNC_DPK_OFFLOAD
        || ReportKind::Txgapk.func() != FUNC_TXGAPK_OFFLOAD
        || ReportKind::Dack.func() != FUNC_DACK_OFFLOAD
        || ReportKind::RxDck.func() != FUNC_RXDCK_OFFLOAD
        || ReportKind::Iqk.name() != "IQK"
        || REPORT_KINDS != 9
    {
        return TestResult::Fail("BE report kinds differ from core.h/fw.h");
    }
    // C2H report parse: OK state + version; anything else rejected.
    if parse_c2h_report(&report_frame(1, 3)) != Some(Model::ok(3)) {
        return TestResult::Fail("BE C2H RFK report parse differs from rtw89_c2h_rfk_report");
    }
    if parse_c2h_report(&report_frame(2, 0))
        != Some(Report {
            state: ReportState::Fail,
            version: 0,
        })
        || parse_c2h_report(&report_frame(9, 0))
            != Some(Report {
                state: ReportState::Fail,
                version: 0,
            })
    {
        return TestResult::Fail("BE C2H report non-OK/unknown state is not Fail");
    }
    let mut wrong_class = report_frame(1, 0);
    wrong_class[0] = 2 | (0x8 << 2);
    let mut wrong_len = report_frame(1, 0);
    wrong_len[4] = 12;
    if parse_c2h_report(&wrong_class).is_some()
        || parse_c2h_report(&wrong_len).is_some()
        || parse_c2h_report(&report_frame(1, 0)[..9]).is_some()
    {
        return TestResult::Fail("BE C2H report parse accepts a non-report message");
    }
    // run(): H2C sent on OUTSRC/RFK class, report waited with the
    // caller's timeout, OK accepted.
    let mut io = Model::new(vec![Model::ok(2)]);
    let got = ready(run(
        &mut io,
        FUNC_IQK_OFFLOAD,
        &[8, 0, 0, 3, 1, 2, 42, 0],
        84,
    ));
    if got != Some(Ok(Model::ok(2)))
        || io.h2c != vec![(2, 0xB, 0x1, vec![8, 0, 0, 3, 1, 2, 42, 0])]
        || io.timeouts != vec![84]
    {
        return TestResult::Fail("BE offload run does not send H2C then wait the report");
    }
    if check(Model::ok(0)) != Ok(Model::ok(0))
        || check(Report {
            state: ReportState::Fail,
            version: 0,
        }) != Err(Error::Report)
    {
        return TestResult::Fail("BE report check does not accept only OK");
    }
    // run() returns a non-OK report for the caller to record, and a
    // missing report is a transport timeout.
    let mut io = Model::new(vec![Report {
        state: ReportState::Timeout,
        version: 0,
    }]);
    if ready(run(&mut io, FUNC_DPK_OFFLOAD, &[8; 8], 34))
        != Some(Ok(Report {
            state: ReportState::Timeout,
            version: 0,
        }))
    {
        return TestResult::Fail("BE offload run hides a non-OK report state");
    }
    let mut io = Model::new(vec![]);
    if ready(run(&mut io, FUNC_DPK_OFFLOAD, &[8; 8], 34))
        != Some(Err(Error::Register(power::Error::Timeout)))
    {
        return TestResult::Fail("BE offload run does not time out on a missing report");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_rfk_offload_bodies_and_report_wait
);
