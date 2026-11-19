// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Native Rust model of the actual A channel owner, with literal source
//! expectations (not a copy of the channel program under test).
use super::*;
use crate::rtw89::{power::Io, radio_assets::Element, rfk};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Write8(u32, u8),
    Write32(u32, u32),
    Rf(u8, u32),
    Delay(u64),
    Pause,
    Resume(u32),
    Coex,
}
struct Model {
    words: Vec<u32>,
    rf18: [u32; 2],
    trace: Vec<Op>,
    now: u64,
    denied: bool,
    fail_write: Option<u32>,
    ignore_write: Option<u32>,
    gone_rf: Option<u8>,
    block_delay: bool,
}
impl Model {
    fn new() -> Self {
        let mut m = Self {
            words: vec![0; 0x20000 / 4],
            rf18: [0x84000, 0x44000],
            trace: Vec::new(),
            now: 0,
            denied: false,
            fail_write: None,
            ignore_write: None,
            gone_rf: None,
            block_delay: false,
        };
        m.words[0xc010 / 4] = 0xa4;
        m.words[0xc628 / 4] = 0x90;
        m.words[0x9c18 / 4] = 0x90;
        m
    }
    fn word(&self, a: u32) -> u32 {
        self.words[a as usize / 4]
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        Ok((self.word(a) >> ((a & 3) * 8)) as u8)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        Ok(self.word(a))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        let shift = (a & 3) * 8;
        let w = &mut self.words[a as usize / 4];
        *w = (*w & !(0xff << shift)) | (u32::from(v) << shift);
        self.trace.push(Op::Write8(a, v));
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        if self.fail_write == Some(a) {
            return Err(power::Error::Access);
        }
        if self.ignore_write != Some(a) {
            self.words[a as usize / 4] = v;
        }
        self.trace.push(Op::Write32(a, v));
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.trace.push(Op::Delay(us));
        if self.block_delay {
            core::future::pending::<()>().await;
        }
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        if self.denied {
            Err(Error::Policy)
        } else {
            Ok(())
        }
    }
    async fn rf_read(&mut self, path: u8, a: u32, mask: u32) -> Result<u32, Error> {
        assert_eq!((a, mask), (0x18, 0xf_ffff));
        if self.gone_rf == Some(path) {
            return Ok(u32::MAX);
        }
        Ok(self.rf18[usize::from(path)])
    }
    async fn rf_write(&mut self, path: u8, a: u32, mask: u32, value: u32) -> Result<(), Error> {
        assert_eq!((a, mask), (0x18, 0xf_ffff));
        self.rf18[usize::from(path)] = value;
        self.trace.push(Op::Rf(path, value));
        Ok(())
    }
    async fn begin(&mut self, _: rfk::Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn end(&mut self, _: rfk::Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.trace.push(Op::Pause);
        Ok(0xa35a)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), Error> {
        self.trace.push(Op::Resume(saved));
        Ok(())
    }
    async fn coex_switch_band(&mut self) -> Result<(), Error> {
        self.trace.push(Op::Coex);
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

/// Complete private, zero-entry firmware elements. They are model input,
/// never a default or a qualification for the production channel owner.
pub(in crate::rtw89) fn power_plan(profile: Profile) -> Plan {
    let elements: Vec<_> = [(9, 9), (10, 7), (11, 7), (13, 5), (14, 5), (16, 4)]
        .into_iter()
        .map(|(id, size)| Element {
            id,
            version: [0; 4],
            bytes: vec![0, 0, 0, size, 0, 0, 0, 0],
        })
        .collect();
    Plan::from_elements_a(&elements, 0, profile).unwrap()
}
fn program(
    channel: &mut Channel,
    model: &mut Model,
    profile: Profile,
) -> Option<Result<(), Error>> {
    let plan = power_plan(profile);
    // SAFETY: private inert RAM model; no native producer or emission.
    ready(unsafe { channel.set_channel(model, profile, &plan) })
}

fn smoke_rtw8852a_channel20_mac_bb_rf_and_power() -> TestResult {
    let mut channel = Channel::default();
    let mut io = Model::new();
    io.words[0xd2c0 / 4] = u32::MAX; // full writes do not require an old value.
    kt_assert_eq!(
        program(&mut channel, &mut io, Profile::INITIAL),
        Some(Ok(()))
    );
    kt_assert_eq!(channel.state(), State::Programmed);
    kt_assert_eq!(channel.programmed(), Some(Profile::INITIAL));
    kt_assert_eq!(io.rf18, [0x84c01, 0x44c01]);
    kt_assert_eq!(io.word(0xc010), 0xa4);
    kt_assert_eq!(io.word(0xc088), 0);
    kt_assert_eq!(io.word(0xc628), 0x90); // BAND_MODE preserved.
    kt_assert_eq!(io.word(0x123b0), 0x1cfea);
    kt_assert_eq!(io.word(0x123b4), 0x27de3);
    kt_assert_eq!(io.word(0x14644), 1 << 30);
    kt_assert_eq!(io.word(0x14718), 1 << 30);
    kt_assert_eq!(io.word(0x14974), 109);
    kt_assert_eq!(io.word(0x12300), 0x3d23ff);
    kt_assert_eq!(io.word(0x12304), 0x29b354);
    kt_assert_eq!(io.word(0x10734), 1 << 16);
    kt_assert_eq!(io.word(0x112ec), 0x20);
    kt_assert_eq!(io.word(0x132ec), 0x20);
    // set_txpwr_ref belongs to DM init; channel changes do not repeat it.
    kt_assert_eq!(io.word(0x15804), 0);
    kt_assert_eq!(io.word(0x17808), 0);
    kt_assert_eq!(io.word(0xd2c0), 0);
    kt_assert_eq!(io.word(0xce40), 0x2b);
    kt_assert_eq!(io.word(0x9c18), 0x92);
    kt_assert_eq!(io.word(0x120fc), 0);
    kt_assert_eq!(io.word(0x10000), 1 << 31);
    kt_assert_eq!(io.trace.first(), Some(&Op::Pause));
    kt_assert_eq!(
        io.trace[io.trace.len() - 2..],
        [Op::Resume(0xa35a), Op::Coex]
    );
    kt_assert_eq!(io.trace.iter().filter(|o| **o == Op::Delay(40)).count(), 1);
    // Exact A source ordering: the power tail precedes PPDU/help exit.
    let power = io
        .trace
        .iter()
        .position(|o| *o == Op::Write32(0xd368, 0))
        .unwrap();
    let leave = io
        .trace
        .iter()
        .position(|o| *o == Op::Write32(0xce40, 0x2b))
        .unwrap();
    kt_assert!(power < leave);
    kt_assert!(!io
        .trace
        .iter()
        .any(|o| matches!(o, Op::Write32(0x14494, _))));
    TestResult::Pass
}

fn smoke_rtw8852a_channel_wide_spurs_and_source_sco() -> TestResult {
    for (width, center, notch, csi, subcarrier, pri) in [
        (Width::Mhz20, 153, 0x210, 0x7c0, 0, 0),
        (Width::Mhz40, 151, 0x210, 0x40, 2, 2),
        (Width::Mhz80, 155, 0x2d0, 0x740, 0xa4, 4),
    ] {
        let primary = if width == Width::Mhz20 { 153 } else { 149 };
        let profile = Profile::new_5ghz(primary, width).unwrap();
        let mut channel = Channel::default();
        let mut io = Model::new();
        kt_assert_eq!(profile.center(), center);
        kt_assert_eq!(program(&mut channel, &mut io, profile), Some(Ok(())));
        kt_assert_eq!(io.word(0xc628), 0x93);
        kt_assert_eq!(io.word(0xc088), subcarrier);
        kt_assert_eq!(io.word(0x14978) & 0xf00, pri << 8);
        kt_assert_eq!(io.word(0x1469c) & 0x1fff, 0x1000 | notch);
        kt_assert_eq!(io.word(0x14770) & 0x1fff, 0x1000 | notch);
        kt_assert_eq!(io.word(0x142ac) & 0x7ff, csi);
        kt_assert_eq!(io.word(0x142c4) & (1 << 23), 1 << 23);
        kt_assert_eq!(io.word(0x10734) & 0xff_0000, u32::from(primary) << 16);
        kt_assert_eq!(io.word(0x12344), 1 << 31);
        kt_assert!(io.trace.contains(&Op::Delay(1)));
        if width == Width::Mhz80 {
            kt_assert_eq!(io.rf18, [0x9459b, 0x5459b]);
        }
        // A source disables the notch controls without erasing their indices.
        let plain = Profile::new_5ghz(36, Width::Mhz20).unwrap();
        kt_assert_eq!(program(&mut channel, &mut io, plain), Some(Ok(())));
        kt_assert_eq!(io.word(0x1469c) & 0x1fff, notch);
        kt_assert_eq!(io.word(0x142c4) & (1 << 23), 0);
    }
    for (primary, secondary_above, barker, cck, rxsc) in [
        (1, true, 0x1d3c3, 0x2832d, 0),
        (5, false, 0x1cfea, 0x27de3, 1),
    ] {
        let profile = Profile::new_2ghz_40(primary, secondary_above).unwrap();
        let mut io = Model::new();
        kt_assert_eq!(
            program(&mut Channel::default(), &mut io, profile),
            Some(Ok(()))
        );
        kt_assert_eq!(io.word(0x123b0), barker);
        kt_assert_eq!(io.word(0x123b4), cck);
        kt_assert_eq!(io.word(0x1237c), rxsc);
    }
    TestResult::Pass
}

fn smoke_rtw8852a_channel_failed_access_does_not_resume() -> TestResult {
    for fault in 0..4 {
        let mut io = Model::new();
        let mut channel = Channel::default();
        match fault {
            0 => io.denied = true,
            1 => io.gone_rf = Some(1),
            2 => io.ignore_write = Some(0x112ec),
            _ => io.fail_write = Some(0xd2c0),
        }
        kt_assert!(matches!(
            program(&mut channel, &mut io, Profile::INITIAL),
            Some(Err(_))
        ));
        kt_assert_eq!(channel.state(), State::Busy);
        kt_assert_eq!(channel.programmed(), None);
        kt_assert!(!io.trace.iter().any(|o| matches!(o, Op::Resume(_))));
        let writes = io.trace.len();
        io.denied = false;
        kt_assert_eq!(
            program(&mut channel, &mut io, Profile::INITIAL),
            Some(Err(Error::Terminal))
        );
        kt_assert_eq!(io.trace.len(), writes);
    }
    // A plan for another channel is refused before the first access.
    let mut channel = Channel::default();
    let mut io = Model::new();
    let wrong = power_plan(Profile::new_5ghz(36, Width::Mhz20).unwrap());
    kt_assert_eq!(
        // SAFETY: private inert model; intentionally mismatched pure plan.
        ready(unsafe { channel.set_channel(&mut io, Profile::INITIAL, &wrong) }),
        Some(Err(Error::Policy))
    );
    kt_assert!(io.trace.is_empty());
    kt_assert_eq!(channel.state(), State::New);
    let unsupported = Profile::new_5ghz_160(36).unwrap();
    kt_assert_eq!(
        // SAFETY: private inert model; unsupported geometry is refused before I/O.
        ready(unsafe { channel.set_channel(&mut io, unsupported, &wrong) }),
        Some(Err(Error::Policy))
    );
    kt_assert!(io.trace.is_empty());
    TestResult::Pass
}

fn smoke_rtw8852a_channel_cancelled_help_wait_is_terminal() -> TestResult {
    let mut channel = Channel::default();
    let mut io = Model::new();
    io.block_delay = true;
    let plan = power_plan(Profile::INITIAL);
    {
        // SAFETY: private inert model; cancel during the real help wait.
        let mut f = pin!(unsafe { channel.set_channel(&mut io, Profile::INITIAL, &plan) });
        kt_assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    kt_assert_eq!(channel.state(), State::Busy);
    kt_assert_eq!(channel.programmed(), None);
    kt_assert_eq!(io.trace.last(), Some(&Op::Delay(40)));
    kt_assert!(!io.trace.iter().any(|o| matches!(o, Op::Resume(_))));
    let count = io.trace.len();
    io.block_delay = false;
    kt_assert_eq!(
        program(&mut channel, &mut io, Profile::INITIAL),
        Some(Err(Error::Terminal))
    );
    kt_assert_eq!(io.trace.len(), count);
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_channel20_mac_bb_rf_and_power
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_channel_wide_spurs_and_source_sco
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_channel_failed_access_does_not_resume
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_channel_cancelled_help_wait_is_terminal
);
