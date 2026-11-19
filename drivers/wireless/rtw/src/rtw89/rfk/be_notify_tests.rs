// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use crate::rtw89::{
    operating_channel_c::{Band, Width},
    power,
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context as PollContext, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
fn ready<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut PollContext::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
fn words(body: &Body) -> Vec<u32> {
    body.bytes()
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect()
}
fn smoke_rtw8922a_versioned_notify_literal_context_layouts() -> TestResult {
    // Sentinel records deliberately differ by path/table, proving source
    // row-major PRE and transposed MCC-v0 storage rather than just lengths.
    let mut context = Context::default();
    for path in 0..2 {
        for table in 0..3 {
            context.paths[path].records[table] = Record {
                channel: (10 + path * 3 + table) as u8,
                band: (20 + path * 3 + table) as u8,
                bandwidth: (30 + path * 3 + table) as u8,
                rf18: (40 + path * 3 + table) as u32,
            };
        }
    }
    context.paths[0].selected = 1;
    context.paths[1].selected = 2;
    let v0 = Features::fixture([0, 35, 27, 0]);
    kt_assert_eq!(
        words(&context.pre_body(v0).unwrap()),
        vec![
            10, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24, 25, 1, 11, 15, 21, 25, 0, 21, 31, 11, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
    let v1 = Features::fixture([0, 35, 31, 0]);
    kt_assert_eq!(
        words(&context.pre_body(v1).unwrap()),
        vec![10, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24, 25, 1, 11, 15, 21, 25, 0, 0,]
    );
    let v2 = Features::fixture([0, 35, 49, 0]);
    kt_assert_eq!(
        words(&context.pre_body(v2).unwrap()),
        vec![10, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24, 25, 1, 11, 15, 21, 25, 0, 0, 31, 35,]
    );
    kt_assert_eq!(
        words(&context.mcc_body(v2).unwrap()),
        vec![40, 43, 41, 44, 42, 45, 41, 45, 1,]
    );
    let current = Features::fixture([0, 35, 84, 0]);
    kt_assert!(context.pre_body(current).is_none());
    let body = context.mcc_body(current).unwrap();
    kt_assert_eq!(
        body.bytes(),
        &[
            40, 0, 0, 0, 41, 0, 0, 0, 42, 0, 0, 0, 41, 0, 0, 0, 42, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]
    );
    kt_assert!(context.mcc_body(v1).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_versioned_notify_literal_context_layouts
);

#[derive(Default)]
struct Model {
    words: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32)>,
    rf: Vec<(u8, u32, u32, u32)>,
    h2c: Vec<(u8, u8, u8, Vec<u8>)>,
    waits: Vec<u64>,
    count: usize,
    fail_at: Option<usize>,
    failed: bool,
    pending: bool,
}
impl Model {
    fn effect(&mut self) -> Result<(), power::Error> {
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
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.effect()?;
        Ok(*self.words.get(&address).unwrap_or(&0))
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.effect()?;
        self.words.insert(address, value);
        self.writes.push((address, value));
        Ok(())
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        self.effect().map_err(Error::from)
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        self.effect()?;
        if address != 0x18 || mask != 0xfffff {
            return Err(Error::Table);
        }
        Ok(if path == 0 { 0x12345 } else { 0x6789a })
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.effect()?;
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.rf.push((path, address, mask, value));
        Ok(())
    }
    async fn begin(&mut self, _: super::super::Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn end(&mut self, _: super::super::Kind) -> Result<(), Error> {
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        Ok(0)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        Ok(())
    }
    async fn h2c(&mut self, cat: u8, class: u8, func: u8, payload: &[u8]) -> Result<(), Error> {
        self.effect()?;
        self.h2c.push((cat, class, func, payload.to_vec()));
        Ok(())
    }
    async fn await_rfk_report(&mut self, ms: u64) -> Result<Report, Error> {
        self.effect()?;
        self.waits.push(ms);
        Ok(Report {
            state: be_rfk::ReportState::Ok,
            version: 7,
        })
    }
}
fn smoke_rtw8922a_source_reload_and_versioned_notify_current_failure() -> TestResult {
    let profile = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80).unwrap();
    let features = Features::fixture([0, 35, 27, 0]);
    let mut io = Model::default();
    let mut context = Context::default();
    kt_assert!(!context.matches(profile, features));
    // SAFETY: inert model with no real device; explicit source SCC profile.
    let reload = unsafe { context.reload(&mut io, profile, features) };
    kt_assert_eq!(ready(reload), Some(Ok(())));
    kt_assert!(context.matches(profile, features));
    kt_assert_eq!(
        io.writes,
        vec![
            (0x28104, 0x80000000),
            (0x28104, 0x80000000),
            (0x28104, 0x80000000),
            (0x28154, 0),
            (0x28154, 0),
            (0x28204, 0x80000000),
            (0x28204, 0x80000000),
            (0x28204, 0x80000000),
            (0x28254, 0),
            (0x28254, 0),
        ]
    );
    kt_assert_eq!(io.rf, vec![(0, 1, 0xe0000, 4), (1, 1, 0xe0000, 4)]);
    let accesses = io.count;
    for at in 1..=accesses {
        let mut bad = Model {
            fail_at: Some(at),
            ..Model::default()
        };
        let mut owner = Context::default();
        // SAFETY: independent inert register/RF model.
        let reload = unsafe { owner.reload(&mut bad, profile, features) };
        kt_assert!(matches!(ready(reload), Some(Err(_))));
        kt_assert!(!owner.matches(profile, features));
        let effects = (bad.writes.len(), bad.rf.len());
        // SAFETY: same failed inert owner; no actual device exists.
        let retry = unsafe { owner.reload(&mut bad, profile, features) };
        kt_assert!(matches!(ready(retry), Some(Err(_))));
        kt_assert_eq!((bad.writes.len(), bad.rf.len()), effects);
    }
    io.words.insert(0x28104, 2);
    io.words.insert(0x28204, 1);
    kt_assert_eq!(
        ready(pre(&mut io, features, &context, 0x5a)),
        Some(Ok(Some(Report {
            state: be_rfk::ReportState::Ok,
            version: 7
        })))
    );
    kt_assert_eq!(
        &io.h2c[0].3[84..108],
        &[2, 0, 0, 0, 1, 0, 0, 0, 0x45, 0x23, 1, 0, 0x9a, 0x78, 6, 0, 0, 0, 0, 0, 0x5a, 0, 0, 0,]
    );
    kt_assert_eq!(io.waits, vec![5]);
    let latest = Features::fixture([0, 35, 84, 0]);
    kt_assert_eq!(ready(pre(&mut io, latest, &context, 0x5a)), Some(Ok(None)));
    kt_assert_eq!(ready(mcc(&mut io, latest, &context)), Some(Ok(())));
    kt_assert_eq!(
        (io.h2c[1].0, io.h2c[1].1, io.h2c[1].2, io.h2c[1].3.len()),
        (2, 0xa, 0xf, 30)
    );
    kt_assert_eq!(io.waits, vec![5]); // MCC never arms a report wait.
    let mut pending = Model {
        pending: true,
        ..Model::default()
    };
    let mut held = Context::default();
    // SAFETY: inert pending RF model; dropping must retain terminal busy.
    let dropped = unsafe { held.reload(&mut pending, profile, features) };
    kt_assert_eq!(ready(dropped), None);
    kt_assert!(!held.matches(profile, features));
    // SAFETY: same retained inert owner after cancelled pending RF effect.
    let retry = unsafe { held.reload(&mut pending, profile, features) };
    kt_assert_eq!(ready(retry), Some(Err(Error::Terminal)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_source_reload_and_versioned_notify_current_failure
);
