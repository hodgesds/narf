// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Write(u32, u32),
    XtalWrite(u8, u8, u8),
    XtalRead(u8),
    Thermal(u8),
    RfWrite(u8, u32, u32, u32),
    RfRead(u8, u32, u32),
    Delay(u64),
}
struct Model {
    words: BTreeMap<u32, u32>,
    xtal: BTreeMap<u8, u8>,
    events: Vec<Event>,
    count: usize,
    fail_at: Option<usize>,
    failed: bool,
    drop_xtal: bool,
    thermal_raw: u32,
}
impl Model {
    fn new() -> Self {
        let mut words = BTreeMap::new();
        for page in 0..17 {
            words.insert(
                if page == 16 {
                    0x20788
                } else {
                    0x2073c + page * 4
                },
                0x1f0,
            );
        }
        Self {
            words,
            xtal: [(0xe1, 1), (0xd1, 0x7f), (0x16, 0x80)]
                .into_iter()
                .collect(),
            events: Vec::new(),
            count: 0,
            fail_at: None,
            failed: false,
            drop_xtal: false,
            thermal_raw: 0,
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        if self.failed {
            return Err(power::Error::Access);
        }
        self.count += 1;
        if self.fail_at == Some(self.count) {
            self.failed = true;
            return Err(power::Error::Access);
        }
        Ok(())
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
        self.access()?;
        if (0x14000..0x18000).contains(&a) {
            return Err(power::Error::Access);
        }
        Ok(*self.words.get(&a).unwrap_or(&0))
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        if (0x14000..0x18000).contains(&a) {
            return Err(power::Error::Access);
        }
        self.words.insert(a, v);
        self.events.push(Event::Write(a, v));
        Ok(())
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, us: u64) {
        self.events.push(Event::Delay(us));
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl phy_operating::Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        self.access().map_err(Error::from)
    }
    async fn xtal_write(&mut self, a: u8, v: u8, m: u8) -> Result<(), Error> {
        self.access()?;
        self.events.push(Event::XtalWrite(a, v, m));
        if !self.drop_xtal {
            let old = *self.xtal.get(&a).unwrap_or(&0);
            self.xtal.insert(a, (old & !m) | (v & m));
        }
        Ok(())
    }
    async fn xtal_read(&mut self, a: u8) -> Result<u8, Error> {
        self.access()?;
        self.events.push(Event::XtalRead(a));
        Ok(*self.xtal.get(&a).unwrap_or(&0))
    }
}
impl Interface for Model {
    async fn thermal(&mut self, path: u8) -> Result<Thermal, Error> {
        self.access()?;
        self.events.push(Event::Thermal(path));
        Ok(Thermal::DisabledByProfile)
    }
}
impl super::super::rfk::Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        self.access().map_err(Into::into)
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        self.access()?;
        self.events.push(Event::RfRead(path, address, mask));
        Ok(self.thermal_raw)
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.access()?;
        self.events.push(Event::RfWrite(path, address, mask, value));
        Ok(())
    }
    async fn begin(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Policy)
    }
    async fn end(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Policy)
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        Err(Error::Policy)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Policy)
    }
}
fn smoke_rtw8922a_thermal_is_actual_source_trigger_trim_clamp_or_typed_fallback() -> TestResult {
    for (path, raw, trim, expected) in [
        (0, 5, [-9, 7], 0),
        (1, 250, [-9, 7], 255),
        (0, 100, [-9, 7], 91),
        (1, 100, [-9, 7], 107),
    ] {
        let mut io = Model::new();
        io.thermal_raw = raw;
        kt_assert_eq!(
            ready(source_thermal(&mut io, path, 0xb4, trim)),
            Some(Ok(Thermal::Measured(expected)))
        );
        kt_assert_eq!(
            io.events,
            vec![
                Event::RfWrite(path, 0x42, 0x80000, 1),
                Event::RfWrite(path, 0x42, 0x80000, 0),
                Event::RfWrite(path, 0x42, 0x80000, 1),
                Event::Delay(200),
                Event::RfRead(path, 0x42, 0xff),
            ]
        );
        let count = io.count;
        for at in 1..=count {
            let mut broken = Model::new();
            broken.fail_at = Some(at);
            kt_assert!(matches!(
                ready(source_thermal(&mut broken, path, 0xb4, trim)),
                Some(Err(_))
            ));
            let before = broken.events.clone();
            kt_assert!(matches!(
                ready(source_thermal(&mut broken, path, 0xb4, trim)),
                Some(Err(_))
            ));
            kt_assert_eq!(broken.events, before);
        }
    }
    let mut disabled = Model::new();
    disabled.thermal_raw = 233;
    kt_assert_eq!(
        ready(source_thermal(&mut disabled, 0, 0, [-7, 7])),
        Some(Ok(Thermal::DisabledByProfile))
    );
    kt_assert!(disabled.events.is_empty());
    kt_assert_eq!(
        ready(source_thermal(&mut disabled, 2, 0xb4, [0; 2])),
        Some(Err(Error::Policy))
    );
    kt_assert!(disabled.events.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_thermal_is_actual_source_trigger_trim_clamp_or_typed_fallback
);
fn ready<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn factory() -> BeFactory {
    BeFactory {
        mac: [2, 1, 2, 3, 4, 5],
        rfe_type: 1,
        xtal_cap: 0x3a,
        country: *b"US",
        phycap: [0; crate::rtw89::chip_8922a::PHYCAP_SIZE],
        cv: Some(0),
        thermal_k: None,
        secure: crate::rtw89::efuse_be::SecureInfo::disabled(),
    }
}
fn identity() -> HalChipVer {
    HalChipVer {
        cv: 0,
        acv: 1,
        cid: crate::rtw89::mac_pre_init_8922a::Cid::Unknown(0x56),
        aid: 0x1234,
    }
}
fn smoke_rtw8922a_bb_postinit_is_complete_source_scc_program() -> TestResult {
    let expected = [
        (0x84, 4),
        (0x84, 5),
        (0x20000, 4),
        (0x26284, 0),
        (0x2627c, 0x80000),
        (0x26b6c, 0xa0000000),
        (0x26bfc, 0x50000000),
        (0x26c00, 0xaaa),
        (0x26bfc, 0xd0000000),
        (0x26c00, 0x80000aaa),
        (0x26c04, 0),
        (0x26c04, 0),
        (0x26c04, 0),
        (0x26c04, 0),
        (0x26c08, 2),
        (0x26c10, 0x2000000),
        (0x26c10, 0x2100000),
        (0x26bf8, 0x1000000),
        (0x26bf4, 0xe0000000),
        (0x26bf8, 0x1e0c000),
        (0x26b6c, 0xa0003fe0),
        (0x26b6c, 0xaff83fe0),
        (0x26b70, 0x200),
        (0x20cbc, 0),
        (0x20cbc, 0x80000),
    ];
    let mut io = Model::new();
    kt_assert_eq!(post_bb(&mut io), Ok(()));
    let writes: Vec<_> = io
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Write(address, value) => Some((*address, *value)),
            _ => None,
        })
        .collect();
    kt_assert_eq!(writes.as_slice(), expected.as_slice());
    let accesses = io.count;
    for fault in 1..=accesses {
        let mut broken = Model::new();
        broken.fail_at = Some(fault);
        kt_assert!(post_bb(&mut broken).is_err());
        let before = broken.events.clone();
        kt_assert!(post_bb(&mut broken).is_err());
        kt_assert_eq!(broken.events, before);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_bb_postinit_is_complete_source_scc_program
);
fn smoke_rtw8922a_be_dm_literal_source_program_and_explicit_partial_state() -> TestResult {
    let board = factory();
    let mut io = Model::new();
    let mut owner = Operating::default();
    // SAFETY: inert exclusive source program model; no hardware or grant.
    let result = unsafe { owner.prepare_scc_partial(&mut io, &board, identity()) };
    kt_assert_eq!(ready(result), Some(Ok(())));
    kt_assert_eq!(owner.state(), State::PartialMac1Off);
    kt_assert_eq!(
        &io.events[..14],
        &[
            Event::Thermal(0),
            Event::Thermal(1),
            Event::Write(0x2047c, 0),
            Event::Write(0x2147c, 0),
            Event::Write(0x11a40, 0),
            Event::Write(0x26b48, 0),
            Event::Write(0x2703c, 0x1000),
            Event::Write(0x22a5c, 0x70000000),
            Event::Write(0x22a60, 7),
            Event::Write(0x22b5c, 0x70000000),
            Event::Write(0x22b60, 7),
            Event::Write(0x20044, 0x06180000),
            Event::Write(0x20044, 0x00180000),
            Event::Write(0x20044, 0),
        ]
    );
    for (page, value) in [
        (6, 0x21f0),
        (7, 0x21f0),
        (9, 0x1f0),
        (10, 0x21f2),
        (11, 0x102),
        (12, 0x100),
        (13, 0x100100),
        (16, 0x100100),
    ] {
        let address = if page == 16 {
            0x20788
        } else {
            0x2073c + page * 4
        };
        kt_assert_eq!(io.words.get(&address).copied(), Some(value));
    }
    kt_assert_eq!(io.words.get(&0x26708).copied(), Some(0x82000000)); // BE -126, not AX -128.
    kt_assert_eq!(io.words.get(&0x26260).copied(), Some(0x20000));
    kt_assert_eq!(io.words.get(&0x26244).copied(), Some(0x80000000));
    kt_assert_eq!(io.words.get(&0x20cc8).copied(), Some(0x2900));
    for address in (0xe500..0xe580)
        .step_by(4)
        .chain((0xed00..0xed80).step_by(4))
    {
        kt_assert_eq!(io.words.get(&address).copied(), Some(0));
    }
    kt_assert!(!io
        .events
        .iter()
        .any(|op| matches!(op, Event::Write(0x15a78 | 0x15a84, _))));
    let analog: Vec<_> = io
        .events
        .iter()
        .filter(|op| matches!(op, Event::XtalWrite(..) | Event::XtalRead(..)))
        .copied()
        .collect();
    kt_assert_eq!(
        analog,
        vec![
            Event::XtalWrite(5, 0x3a, 255),
            Event::XtalWrite(4, 0x3a, 255),
            Event::XtalRead(5),
            Event::XtalRead(4),
            Event::XtalRead(0xe1),
            Event::XtalWrite(0xe1, 0xf9, 255),
            Event::XtalRead(0xd1),
            Event::XtalWrite(0xd1, 0x1f, 255),
            Event::XtalRead(0x16),
            Event::XtalWrite(0x16, 0xb8, 255),
        ]
    );
    kt_assert_eq!(
        owner.partial().unwrap(),
        Working {
            crystal_default: 0x3a,
            crystal_actual: 0x3a,
            crystal_lower: 1,
            crystal_upper: 122,
            thermal: [Thermal::DisabledByProfile; 2]
        }
    );
    let effects = io.events.len();
    // SAFETY: same completed inert owner; no new attempt may be constructed.
    let retry = unsafe { owner.prepare_scc_partial(&mut io, &board, identity()) };
    kt_assert_eq!(ready(retry), Some(Err(Error::Terminal)));
    kt_assert_eq!(io.events.len(), effects);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_be_dm_literal_source_program_and_explicit_partial_state
);
fn smoke_rtw8922a_be_dm_first_error_and_actual_xtal_refusal() -> TestResult {
    let board = factory();
    let mut io = Model::new();
    let mut owner = Operating::default();
    // SAFETY: inert source model used only to bound first-error cases.
    let result = unsafe { owner.prepare_scc_partial(&mut io, &board, identity()) };
    kt_assert_eq!(ready(result), Some(Ok(())));
    for at in 1..=io.count {
        let mut bad = Model::new();
        bad.fail_at = Some(at);
        let mut owner = Operating::default();
        // SAFETY: independent inert register/analog model.
        let result = unsafe { owner.prepare_scc_partial(&mut bad, &board, identity()) };
        kt_assert!(matches!(ready(result), Some(Err(_))));
        kt_assert_eq!(owner.state(), State::Busy);
        kt_assert_eq!(owner.partial(), None);
        let effects = bad.events.len();
        // SAFETY: retained failed inert owner; no hardware exists.
        let retry = unsafe { owner.prepare_scc_partial(&mut bad, &board, identity()) };
        kt_assert_eq!(ready(retry), Some(Err(Error::Terminal)));
        kt_assert_eq!(bad.events.len(), effects);
    }
    let mut ignored = Model::new();
    ignored.drop_xtal = true;
    let mut owner = Operating::default();
    // SAFETY: inert ignored-write model, readback must not be fabricated.
    let result = unsafe { owner.prepare_scc_partial(&mut ignored, &board, identity()) };
    kt_assert_eq!(ready(result), Some(Err(Error::Terminal)));
    kt_assert_eq!(owner.partial(), None);
    kt_assert!(!ignored
        .events
        .iter()
        .any(|op| matches!(op, Event::XtalRead(0xe1))));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_be_dm_first_error_and_actual_xtal_refusal
);
