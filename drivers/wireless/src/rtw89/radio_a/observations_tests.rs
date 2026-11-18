// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use crate::rtw89::{factory_a::Fem, power, rfk::Kind};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Write(u8, u32, u32, u32),
    Delay(u64),
    Read(u8, u32, u32),
    BbRead(u32),
}
#[derive(Default)]
struct Model {
    sample: [u32; 2],
    events: Vec<Event>,
    fail_after: Option<usize>,
    stall: bool,
}
impl power::Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        let path = match address {
            0x11c10 => 0,
            0x13c10 => 1,
            _ => return Err(power::Error::Access),
        };
        self.events.push(Event::BbRead(address));
        Ok(self.sample[path] << 24)
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
    async fn delay_us(&mut self, us: u64) {
        self.events.push(Event::Delay(us));
        if self.stall {
            core::future::pending::<()>().await;
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Access)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        if self.fail_after.is_some_and(|at| self.events.len() >= at) {
            Err(power::Error::Access.into())
        } else {
            Ok(())
        }
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.admit()?;
        self.events.push(Event::Write(path, address, mask, value));
        Ok(())
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        self.admit()?;
        self.events.push(Event::Read(path, address, mask));
        Ok(self.sample[usize::from(path)])
    }
    async fn begin(&mut self, _: Kind) -> Result<(), Error> {
        Err(Error::Terminal)
    }
    async fn end(&mut self, _: Kind) -> Result<(), Error> {
        Err(Error::Terminal)
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        Err(Error::Terminal)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Terminal)
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw8852a_fem_literal_source_switch_uses_band_flags() -> TestResult {
    for rfe in 0..=254 {
        let got = Fem::from_rfe(rfe).unwrap();
        let two = [11, 12, 17, 18, 51, 53].contains(&rfe);
        let five = two || [9, 10, 15, 16].contains(&rfe);
        if got.epa != [two, five] || got.elna != [two, five] {
            return TestResult::Fail("A FEM source RFE switch/fallthrough differs");
        }
    }
    let wrong = crate::rtw89::station_control::tests::factory_with_chip(
        crate::rtw89::mac::ChipId::Rtl8852B,
        false,
    );
    if Fem::from_rfe(255).is_some() || Fem::from_identity(wrong.identity().unwrap()).is_some() {
        return TestResult::Fail("A FEM accepted erased/non-A factory facts");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_fem_literal_source_switch_uses_band_flags
);

fn smoke_rtw8852a_non_tssi_observations_match_source_and_retain_zero_ewma() -> TestResult {
    let mut io = Model {
        sample: [22, 42],
        ..Model::default()
    };
    let mut owner = Observations::default();
    // SAFETY: inert source-only model, no hardware/packets/TSSI/reset.
    if ready(unsafe { owner.non_tssi(&mut io) }) != Some(Ok(())) {
        return TestResult::Fail("A live observation source model refused");
    }
    let expected = vec![
        Event::Write(0, 0x42, 0x80000, 1),
        Event::Write(0, 0x42, 0x80000, 0),
        Event::Write(0, 0x42, 0x80000, 1),
        Event::Delay(200),
        Event::Read(0, 0x42, 0x7e),
        Event::Write(1, 0x42, 0x80000, 1),
        Event::Write(1, 0x42, 0x80000, 0),
        Event::Write(1, 0x42, 0x80000, 1),
        Event::Delay(200),
        Event::Read(1, 0x42, 0x7e),
    ];
    if io.events != expected
        || owner.snapshot()
            != Some(Snapshot {
                sample: [22, 42],
                average: [22, 42],
                last_thermal_max: 42,
            })
    {
        return TestResult::Fail("A RF42 trigger/delay/sample order differs");
    }
    io.sample = [30, 0];
    // SAFETY: same retained inert owner; still non-TSSI.
    if ready(unsafe { owner.non_tssi(&mut io) }) != Some(Ok(()))
        || owner.snapshot()
            != Some(Snapshot {
                sample: [30, 0],
                average: [24, 42],
                last_thermal_max: 30,
            })
    {
        return TestResult::Fail("A source EWMA/zero-sample retention differs");
    }
    let mut fresh = Observations::default();
    io.sample = [0, 0];
    // SAFETY: independent inert zero-sensor case; no factory default supplied.
    if ready(unsafe { fresh.non_tssi(&mut io) }) != Some(Ok(())) || fresh.averages() != [0, 0] {
        return TestResult::Fail("A zero sensor sample fabricated thermal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_non_tssi_observations_match_source_and_retain_zero_ewma
);

fn smoke_rtw8852a_non_tssi_failure_or_drop_preserves_terminal_history() -> TestResult {
    for at in 0..=10 {
        let mut owner = Observations::default();
        let mut io = Model {
            sample: [22, 42],
            fail_after: Some(at),
            ..Model::default()
        };
        // SAFETY: inert per-effect failure injection only.
        if ready(unsafe { owner.non_tssi(&mut io) }).is_some_and(|v| v.is_ok())
            || owner.state() != State::Busy
            || owner.snapshot().is_some()
            || io.events.len() > at
        {
            return TestResult::Fail("A failed source observation published/retried effects");
        }
        let before = io.events.len();
        io.fail_after = None;
        // SAFETY: inert retry must refuse before any new effect.
        if ready(unsafe { owner.non_tssi(&mut io) }) != Some(Err(Error::Terminal))
            || io.events.len() != before
        {
            return TestResult::Fail("A uncertain observation owner revived");
        }
    }
    let mut owner = Observations::default();
    let mut io = Model {
        sample: [22, 42],
        ..Model::default()
    };
    // SAFETY: initial inert observation to establish retained averages.
    if ready(unsafe { owner.non_tssi(&mut io) }) != Some(Ok(())) {
        return TestResult::Fail("A history setup");
    }
    io.stall = true;
    // SAFETY: same inert owner; drop exactly inside the RF-sensor delay.
    if ready(unsafe { owner.non_tssi(&mut io) }).is_some()
        || owner.state() != State::Busy
        || owner.snapshot().is_some()
        || owner.averages() != [22, 42]
    {
        return TestResult::Fail("A dropped delay lost history or retained freshness");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_non_tssi_failure_or_drop_preserves_terminal_history
);

fn smoke_rtw8852a_tssi_thermal_reads_actual_bb_paths_and_retains_history() -> TestResult {
    let mut io = Model {
        sample: [22, 42],
        ..Model::default()
    };
    let mut owner = Observations::default();
    // SAFETY: inert pre-TSSI source sample followed by its explicit TSSI actor.
    if ready(unsafe { owner.non_tssi(&mut io) }) != Some(Ok(())) {
        return TestResult::Fail("A initial thermal history");
    }
    io.events.clear();
    io.sample = [30, 0];
    // SAFETY: inert model explicitly selects the completed-TSSI source branch.
    if ready(unsafe { owner.tssi(&mut io) }) != Some(Ok(()))
        || io.events != vec![Event::BbRead(0x11c10), Event::BbRead(0x13c10)]
        || owner.snapshot()
            != Some(Snapshot {
                sample: [30, 0],
                average: [24, 42],
                last_thermal_max: 30,
            })
    {
        return TestResult::Fail("A TSSI thermal used RF trigger or discarded EWMA");
    }
    io.events.clear();
    io.fail_after = Some(1);
    io.sample = [34, 50];
    // SAFETY: current authority disappears after the actual first BB read.
    if ready(unsafe { owner.tssi(&mut io) }).is_some_and(|result| result.is_ok())
        || io.events != vec![Event::BbRead(0x11c10)]
        || owner.snapshot().is_some()
        || owner.state() != State::Busy
        || owner.averages() != [24, 42]
    {
        return TestResult::Fail("A interrupted BB thermal published/reused stale sample");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_tssi_thermal_reads_actual_bb_paths_and_retains_history
);
