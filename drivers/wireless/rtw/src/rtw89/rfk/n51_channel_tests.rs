use super::super::Kind;
use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Inert model that refuses every access: proves a path performs none.
struct Refuse;
impl power::Io for Refuse {
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
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Refuse {
    fn admit(&mut self) -> Result<(), Error> {
        Err(Error::Policy)
    }
    async fn rf_read(&mut self, _: u8, _: u32, _: u32) -> Result<u32, Error> {
        Err(Error::Policy)
    }
    async fn rf_write(&mut self, _: u8, _: u32, _: u32, _: u32) -> Result<(), Error> {
        Err(Error::Policy)
    }
    async fn begin(&mut self, _: Kind) -> Result<(), Error> {
        Err(Error::Policy)
    }
    async fn end(&mut self, _: Kind) -> Result<(), Error> {
        Err(Error::Policy)
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        Err(Error::Policy)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Policy)
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

fn smoke_rtw89_n51_set_channel_help_follows_rtw8851b() -> TestResult {
    // Enter: PPDU status off, path-A TSSI cont off (MANON 1, TRK_EN 1),
    // ADC FIFO reset 0xf, 40us, RXCCA/PD_HIT disable, S0 HW-SI 7, 1us,
    // RSTB_ASYNC 0. No path-B (0x78dc/0x7818/0x3200) or DFS step.
    let want = [
        Step::Write(0xce40, 1, 0),
        Step::Write(0x1_58dc, 1 << 30, 1),
        Step::Write(0x1_5818, 1 << 30, 1),
        Step::Write(0x1_20fc, 0xff00_0000, 0xf),
        Step::Delay(40),
        Step::Write(0x1_2344, 1 << 31, 1),
        Step::Write(0x1_0c3c, 1 << 9, 1),
        Step::Write(0x1_1200, 0x7000_0000, 7),
        Step::Delay(1),
        Step::Write(0x1_0704, 2, 0),
    ];
    if HELP_ENTER != want {
        return TestResult::Fail("help enter differs from rtw8851b_set_channel_help");
    }
    let two = help_exit(true);
    let five = help_exit(false);
    let head = [
        Step::Write(0xce40, u32::MAX, 0x2b),
        Step::Write(0x9c18, 3, 2),
        Step::Write(0x1_20fc, 0xff00_0000, 0),
        Step::Write(0x1_58dc, 1 << 30, 0),
        Step::Write(0x1_5818, 1 << 30, 0),
        Step::Write(0x1_1200, 0x7000_0000, 0),
        Step::Write(0x1_0704, 2, 1),
    ];
    if two[..7] != head || five[..7] != head {
        return TestResult::Fail("help exit head differs from rtw8851b_set_channel_help");
    }
    // bb_reset_en(true) re-enables RX CCA only on 2.4GHz; PD_HIT always.
    if two[7..]
        != [
            Step::Write(0x1_2344, 1 << 31, 0),
            Step::Write(0x1_0c3c, 1 << 9, 0),
        ]
        || five[7..] != [Step::Write(0x1_0c3c, 1 << 9, 0)]
    {
        return TestResult::Fail("bb_reset_en band rule differs from rtw8851b");
    }
    for step in HELP_ENTER.iter().chain(two.iter()) {
        if let Step::Write(address, _, _) = *step {
            if matches!(address, 0x1_78dc | 0x1_7818 | 0x1_3200) {
                return TestResult::Fail("path-B help write on the one-path RTL8851B");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_set_channel_help_follows_rtw8851b
);

fn smoke_rtw89_n51_channel_owner_gates_rfk_and_scan_tracking() -> TestResult {
    let mut channel = Channel::default();
    if channel.state() != State::New
        || channel.calibrated().is_some()
        || channel.tssi_mode()
        || channel.scanned()
        || channel.conn_rfk()
        || channel.dpk().results().is_some()
        || channel.iqk().results().is_some()
        || channel.tssi().results().is_some()
    {
        return TestResult::Fail("fresh RTL8851B channel owner is not New");
    }
    let mut io = Refuse;
    let mut tracker = Track::new(&Default::default());
    // core.c rtw89_track_work skips while scanning: no access at all.
    // SAFETY: inert refusing model.
    if ready(unsafe { channel.track(&mut io, &mut tracker, true) }) != Some(Ok(false)) {
        return TestResult::Fail("scan-time RF tracking touched the radio");
    }
    // SAFETY: inert refusing model.
    if ready(unsafe { channel.track(&mut io, &mut tracker, false) }) != Some(Err(Error::Terminal)) {
        return TestResult::Fail("RF tracking ran before rfk_channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_channel_owner_gates_rfk_and_scan_tracking
);
