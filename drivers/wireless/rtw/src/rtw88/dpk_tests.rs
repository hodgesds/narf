// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822C DPK calibration/tracking regressions against a byte-addressed
//! register model. Expected values are derived from Linux
//! `rtw8822c.c::rtw8822c_do_dpk`/`rtw8822c_dpk_track`.
use super::dm::{self, Authority, Facts, Period, Tracker};
use super::dpk::Dpk;
use super::firmware_transport::{Error, Io};
use super::packet_format::DataProfile;
use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    cell::Cell,
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const RF_A: u16 = 0x3c00;
const RF_B: u16 = 0x4c00;

struct Regs {
    mem: Vec<u8>,
    writes: Vec<(u16, u32)>,
}
impl Regs {
    fn new() -> Self {
        Self {
            mem: vec![0; 0x10000],
            writes: Vec::new(),
        }
    }
    fn get(&self, r: u16) -> u32 {
        let r = usize::from(r);
        u32::from_le_bytes(self.mem[r..r + 4].try_into().unwrap())
    }
    fn set(&mut self, r: u16, v: u32) {
        let r = usize::from(r);
        self.mem[r..r + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn thermal(&mut self, t: u32) {
        for base in [RF_A, RF_B] {
            self.set(base + 0x42 * 4, t << 1);
        }
    }
    fn channel(&mut self, ch: u32) {
        self.set(RF_A + 0x18 * 4, ch);
    }
}
#[async_trait::async_trait]
// SAFETY: test model with no DMA or hardware.
unsafe impl Io for Regs {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Ok(())
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read8(&mut self, r: u16) -> impl core::future::Future<Output = Result<u8, Error>> + Send {
        async move { Ok(self.mem[usize::from(r)]) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read16(&mut self, r: u16) -> impl core::future::Future<Output = Result<u16, Error>> + Send {
        async move {
            let r = usize::from(r);
            Ok(u16::from_le_bytes([self.mem[r], self.mem[r + 1]]))
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn read32(&mut self, r: u16) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        async move { Ok(self.get(r)) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write8(
        &mut self,
        r: u16,
        v: u8,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            self.mem[usize::from(r)] = v;
            self.writes.push((r, u32::from(v)));
            Ok(())
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write16(
        &mut self,
        r: u16,
        v: u16,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            let a = usize::from(r);
            self.mem[a..a + 2].copy_from_slice(&v.to_le_bytes());
            self.writes.push((r, u32::from(v)));
            Ok(())
        }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn write32(
        &mut self,
        r: u16,
        v: u32,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move {
            // LTE indirect access completes immediately in the model.
            let v = if r == 0x1700 { v | 1 << 29 } else { v };
            self.set(r, v);
            self.writes.push((r, v));
            Ok(())
        }
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::Unsupported)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn delay_us(&mut self, _: u64) {}
}
struct Auth(Cell<bool>);
impl Authority for Auth {
    fn run<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        if self.0.get() {
            op()
        } else {
            Err(Error::Access)
        }
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    let mut f = Box::pin(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
/// Ready one-shot/report/LTE status, channel 1 2.4GHz BW20, thermal 30,
/// STAT_RPT with bit31 ready and DGAIN 1200 (between the 768/1535 bounds).
fn regs() -> Regs {
    let mut r = Regs::new();
    r.set(0x1700, 1 << 29);
    r.set(0x2d9c, 0x55);
    r.set(0x1bfc, 0x8000_0000 | (1200 << 16));
    r.set(0x520, 0x0000_0000);
    r.channel(1);
    r.thermal(30);
    r
}
fn payload(window: u8) -> [u8; 64] {
    let mut p = [0; 64];
    p[..2].copy_from_slice(&dm::DPK.to_le_bytes());
    p[2] = 0x40;
    p[7] = 10;
    p[8] = 50;
    p[9] = window;
    p
}
fn facts() -> Facts {
    Facts {
        did: 0xc822,
        rfe: 0,
        crystal: 0x40,
        thermal: [30, 30],
        power_track_type: 0,
        cck_gi: [10, 20],
    }
}
fn period() -> Period {
    Period {
        linked: true,
        profile: DataProfile {
            rates: 0x15f,
            qos: true,
            mcs: 0xff,
            rx_mcs: 0xff,
            sgi: false,
            ldpc: false,
            stbc: false,
            acs: 0,
            fallback: false,
            bw40: false,
            band5: false,
            vht: None,
        },
        tx_bytes: 0,
        rx_bytes: 0,
        country: *b"US",
        txrx_1ss: false,
    }
}

fn smoke_rtw88_dpk_payload_admission() -> TestResult {
    if dm::bounds(0xc822, &payload(4)).is_none() || dm::bounds(0xc822, &payload(0)).is_none() {
        return TestResult::Fail("C22 DPK payload refused");
    }
    if dm::bounds(0xc821, &payload(4)).is_some() {
        return TestResult::Fail("C21 admitted the RTL8822C-only DPK mechanism");
    }
    let mut big = payload(0x40);
    let mut stray = payload(0);
    stray[..2].copy_from_slice(&dm::DIG.to_le_bytes());
    stray[9] = 1;
    if dm::bounds(0xc822, &big).is_some() || dm::bounds(0xc822, &stray).is_some() {
        return TestResult::Fail("out-of-range or non-DPK window admitted");
    }
    big[9] = 4;
    big[10] = 1;
    if dm::bounds(0xc822, &big).is_some() {
        return TestResult::Fail("nonzero DPK payload tail admitted");
    }
    if Dpk::log2base(0) != 0 || Dpk::log2base(1) != 0 || Dpk::log2base(121_650) != 1685 {
        return TestResult::Fail("rtw8822c_psd_log2base mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dpk",
    smoke_rtw88_dpk_payload_admission
);

fn smoke_rtw88_dpk_calibration_enables_dpd_and_restores_backup() -> TestResult {
    let b = dm::bounds(0xc822, &payload(4)).unwrap();
    let mut t = Tracker::new(b, facts());
    let mut io = regs();
    io.set(0x1d70, 0x2020);
    io.set(0x80c, 0x1234_5670);
    let auth = Auth(Cell::new(true));
    if run(t.tick(&mut io, &auth, period())).is_err() {
        return TestResult::Fail("DPK calibration period failed");
    }
    let Some(d) = t.dpk() else {
        return TestResult::Fail("DPK mechanism did not create a calibrator");
    };
    if d.calibrations() != 1 || d.channel() != 1 || d.path_ok() != [true, true] {
        return TestResult::Fail("DPK result/channel not recorded");
    }
    // gs = DIV_ROUND_CLOSEST((1200 * 910) >> 10, 10) = 107.
    if d.gs() != [107, 107] || io.get(0x1b04) & 0xff != 107 || io.get(0x1b5c) & 0xff != 107 {
        return TestResult::Fail("DPK GS not programmed from the reported DGAIN");
    }
    if io.get(0x1b08) & 1 << 31 == 0 || io.get(0x1b60) & 1 << 31 == 0 {
        return TestResult::Fail("DPD not enabled on both paths after calibration");
    }
    // TX pause and the BB table are undone by the source register restore.
    if io.get(0x520) != 0 || io.get(0x80c) != 0x1234_5670 {
        return TestResult::Fail("DPK BB backup not restored");
    }
    if !io.writes.iter().any(|&(r, v)| r == 0x522 && v == 0xff) {
        return TestResult::Fail("source TX pause not issued");
    }
    // DPK one-shots: DAGC path A = (0x1c << 8) | 0x48.
    if !io.writes.iter().any(|&(r, v)| r == 0x1b00 && v == 0x1c48) {
        return TestResult::Fail("DAGC one-shot command missing");
    }
    // RFK power save re-entered after calibration.
    if io.get(0x1b08) & 1 << 7 != 0 {
        return TestResult::Fail("RFK power save left disabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dpk",
    smoke_rtw88_dpk_calibration_enables_dpd_and_restores_backup
);

fn smoke_rtw88_dpk_track_window_envelope_and_restore() -> TestResult {
    let b = dm::bounds(0xc822, &payload(1)).unwrap();
    let mut t = Tracker::new(b, facts());
    let mut io = regs();
    let auth = Auth(Cell::new(true));
    if run(t.tick(&mut io, &auth, period())).is_err() {
        return TestResult::Fail("calibration period failed");
    }
    // Same thermal: no PWSF change.
    if run(t.tick(&mut io, &auth, period())).is_err() || t.dpk().map(|d| d.pwsf()) != Some([0, 0]) {
        return TestResult::Fail("PWSF changed without a thermal delta");
    }
    // EWMA(10,4) 30 -> 40 reads 32: offset 30-32 = -2, clamped to -1.
    io.thermal(40);
    if run(t.tick(&mut io, &auth, period())).is_err()
        || t.dpk().map(|d| d.pwsf()) != Some([0x7f, 0x7f])
        || io.get(0x1b58) & 0x7f != 0x7f
    {
        return TestResult::Fail("DPK PWSF offset not bounded by the signed window");
    }
    io.thermal(60);
    if run(t.tick(&mut io, &auth, period())) != Err(Error::Prerequisite) {
        return TestResult::Fail("thermal outside the measured envelope accepted");
    }
    if run(t.restore(&mut io, &auth)).is_err()
        || io.get(0x1b58) & 0x7f != 0
        || io.get(0x1b08) & 1 << 31 != 0
        || io.get(0x1b60) & 1 << 31 != 0
    {
        return TestResult::Fail("restore left DPD enabled or a PWSF offset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dpk",
    smoke_rtw88_dpk_track_window_envelope_and_restore
);

fn smoke_rtw88_dpk_recalibrates_on_channel_change() -> TestResult {
    let b = dm::bounds(0xc822, &payload(4)).unwrap();
    let mut t = Tracker::new(b, facts());
    let mut io = regs();
    let auth = Auth(Cell::new(true));
    let _ = run(t.tick(&mut io, &auth, period()));
    let _ = run(t.tick(&mut io, &auth, period()));
    io.channel(6);
    if run(t.tick(&mut io, &auth, period())).is_err() {
        return TestResult::Fail("recalibration failed");
    }
    match t.dpk() {
        Some(d) if d.calibrations() == 2 && d.channel() == 6 => TestResult::Pass,
        _ => TestResult::Fail("channel change did not rerun DPK"),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw88/dpk",
    smoke_rtw88_dpk_recalibrates_on_channel_change
);

fn smoke_rtw88_dpk_lte_timeout_and_revocation_restore() -> TestResult {
    // Revoked authority: no register is touched.
    let b = dm::bounds(0xc822, &payload(4)).unwrap();
    let mut t = Tracker::new(b, facts());
    let mut io = regs();
    if run(t.tick(&mut io, &Auth(Cell::new(false)), period())) != Err(Error::Access)
        || !io.writes.is_empty()
    {
        return TestResult::Fail("revoked DPK authority reached registers");
    }
    // LTE indirect access never ready: fail closed mid-calibration, then the
    // base restore undoes the TX pause from the held backup.
    let mut t = Tracker::new(b, facts());
    let mut io = regs();
    io.set(0x1700, 0);
    let auth = Auth(Cell::new(true));
    if run(t.tick(&mut io, &auth, period())) != Err(Error::Timeout) {
        return TestResult::Fail("stuck LTE indirect access not refused");
    }
    if !io.writes.iter().any(|&(r, v)| r == 0x522 && v == 0xff) {
        return TestResult::Fail("calibration did not reach the TX pause first");
    }
    if run(t.restore(&mut io, &auth)).is_err() || io.get(0x520) != 0 {
        return TestResult::Fail("base restore left TX paused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dpk",
    smoke_rtw88_dpk_lte_timeout_and_revocation_restore
);
