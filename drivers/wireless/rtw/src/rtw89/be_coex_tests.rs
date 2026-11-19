// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
struct Model {
    words: Vec<u32>,
    rf: Vec<(u8, u32, u32, u32)>,
    commands: Vec<(u8, Vec<u8>, bool)>,
    effects: usize,
    checks: usize,
    fail_at: Option<usize>,
    hold: bool,
}
impl Model {
    fn new() -> Self {
        Self {
            words: vec![0; 0x30000 / 4],
            rf: Vec::new(),
            commands: Vec::new(),
            effects: 0,
            checks: 0,
            fail_at: None,
            hold: false,
        }
    }
    fn check(&mut self) -> Result<(), power::Error> {
        self.checks += 1;
        if self.fail_at.is_some_and(|at| self.checks >= at) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
}
impl power::Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.check()?;
        Ok(self.words[a as usize / 4] as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.check()?;
        Ok(self.words[a as usize / 4])
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.check()?;
        self.effects += 1;
        self.words[a as usize / 4] = u32::from(v);
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.check()?;
        self.effects += 1;
        self.words[a as usize / 4] = v;
        Ok(())
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {
        if self.hold {
            core::future::pending::<()>().await;
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl rfk::Interface for Model {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        self.check().map_err(Into::into)
    }
    async fn rf_read(&mut self, _: u8, _: u32, _: u32) -> Result<u32, rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn rf_write(&mut self, p: u8, a: u32, m: u32, v: u32) -> Result<(), rfk::Error> {
        self.check()?;
        self.effects += 1;
        self.rf.push((p, a, m, v));
        Ok(())
    }
    async fn begin(&mut self, _: rfk::Kind) -> Result<(), rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn end(&mut self, _: rfk::Kind) -> Result<(), rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn pause(&mut self) -> Result<u32, rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn resume(&mut self, _: u32) -> Result<(), rfk::Error> {
        Err(rfk::Error::Policy)
    }
}
impl Interface for Model {
    async fn coex_command(&mut self, f: u8, b: &[u8], done: bool) -> Result<(), rfk::Error> {
        self.check()?;
        self.effects += 1;
        self.commands.push((f, b.to_vec(), done));
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
fn smoke_rtw8922a_wlan_source_selected_btc_abi_and_rfe_fields() -> TestResult {
    kt_assert!(Protocol::from_version([0, 35, 7, 255]).is_none());
    kt_assert!(Protocol::from_version([0, 36, 111, 0]).is_none());
    let old = Protocol::from_version([0, 35, 110, 255]).unwrap();
    let modern = Protocol::from_version([0, 35, 111, 0]).unwrap();
    let init = old.init(1, 0, 3, (2, 2)).unwrap();
    kt_assert_eq!(&init[..11], &[0, 7, 24, 6, 1, 1, 0, 0, 0, 0, 0]);
    kt_assert_eq!(
        &init[11..],
        &[1, 0, 0, 1, 1, 4, 3, 0, 0, 2, 10, 0, 0, 1, 2, 0]
    );
    kt_assert_eq!(old.ctrl(), vec![6, 7, 4, 0, 0, 0, 0]);
    let shared = modern.init(2, 0, 3, (1, 2)).unwrap();
    kt_assert_eq!(&shared[..11], &[0, 11, 40, 0, 1, 1, 1, 0, 0, 0, 0]);
    kt_assert_eq!(&shared[19..27], &[0, 2, 10, 0, 2, 4, 1, 0]);
    kt_assert_eq!(shared[28], 1);
    kt_assert_eq!(shared[36], 1);
    let dedicated = modern.init(2, 1, 3, (2, 2)).unwrap();
    kt_assert_eq!(&dedicated[19..27], &[1, 3, 10, 0, 2, 0x44, 1, 0]);
    kt_assert_eq!(dedicated[29], 1);
    kt_assert_eq!(dedicated[36], 0);
    let ctrl = modern.ctrl();
    kt_assert_eq!(&ctrl[..7], &[6, 9, 20, 0, 0, 1, 0]);
    kt_assert_eq!(modern.slots().len(), 3 + 18 * 8);
    kt_assert_eq!(
        &modern.slots()[..11],
        &[1, 7, 18, 100, 0, 0, 0, 0x55, 0x55, 0x55, 0x55]
    );
    kt_assert_eq!(&old.policy()[..11], &[0, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
    kt_assert_eq!(
        &modern.policy()[..14],
        &[0, 12, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    kt_assert_eq!(
        &modern.policy()[14..],
        &[1, 7, 9, 0, 100, 0, 0, 0, 0x55, 0x55, 0x55, 0xe5]
    );
    kt_assert!(modern.init(0, 1, 3, (2, 2)).is_err());
    kt_assert!(modern.init(2, 1, 3, (0, 2)).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_wlan_source_selected_btc_abi_and_rfe_fields
);
fn smoke_rtw8922a_wlan_source_owner_program_notifications_and_terminal_drop() -> TestResult {
    let protocol = Protocol::from_version([0, 35, 111, 0]).unwrap();
    let mut owner = Owner::default();
    let mut io = Model::new();
    // Old host bits cannot become the new source producer's flags.
    io.words[0xac / 4] = 0x4200beef;
    kt_assert_eq!(
        // SAFETY: this sole owner borrows bounded, exclusively owned RAM
        // and modeled RF/command sinks, with no device or competing producer.
        // Command acceptance here supplies no native RF/firmware receipt.
        ready(unsafe { owner.prepare(&mut io, protocol, 1, 0, 2, (2, 2)) }),
        Some(Ok(()))
    );
    kt_assert_eq!(owner.state(), State::WlanOnly);
    kt_assert_eq!(io.words[0xe348 / 4], 0x00d57ddf);
    kt_assert_eq!(io.words[0x1087c / 4], 0x111);
    kt_assert_eq!(io.words[0xac / 4] & 0xffffff, 0x4003);
    kt_assert_eq!(io.words[0xac / 4] & 0x7f000000, 0x43000000);
    kt_assert_eq!(
        io.commands
            .iter()
            .map(|(f, _, d)| (*f, *d))
            .collect::<Vec<_>>(),
        vec![(5, false), (5, false), (1, true), (3, true)]
    );
    kt_assert!(io.rf.contains(&(1, 0x3f, 0xfffff, 0x55f)));
    kt_assert_eq!(ready(owner.notify(&mut io, Some(true))), Some(Ok(())));
    kt_assert_eq!(io.words[0xac / 4] & (1 << 11), 1 << 11);
    kt_assert_eq!(ready(owner.notify(&mut io, Some(false))), Some(Ok(())));
    kt_assert_eq!(io.words[0xac / 4] & (1 << 11), 0);
    let mut held = Model::new();
    held.hold = true;
    let mut dropped = Owner::default();
    kt_assert_eq!(
        // SAFETY: the retained owner and inert RAM model outlive the single
        // poll; ready drops the pending future while the owner stays Busy.
        // No physical maps, source grant or firmware readiness is invented.
        ready(unsafe { dropped.prepare(&mut held, protocol, 1, 0, 2, (2, 2)) }),
        None
    );
    kt_assert_eq!(dropped.state(), State::Busy);
    let effects = held.effects;
    kt_assert_eq!(
        // SAFETY: replay uses the same retained Busy owner/model and must
        // refuse before effects; it cannot adopt a new physical producer.
        ready(unsafe { dropped.prepare(&mut held, protocol, 1, 0, 2, (2, 2)) }),
        Some(Err(rfk::Error::Terminal))
    );
    kt_assert_eq!(held.effects, effects);
    for at in 1..=io.checks {
        let mut owner = Owner::default();
        let mut io = Model::new();
        io.fail_at = Some(at);
        // SAFETY: each fresh owner has exclusive bounded RAM/RF/command
        // sinks. Injected failure retains its Busy state and all modeled
        // resources; this exercises source ordering, not physical authority.
        let result = ready(unsafe { owner.prepare(&mut io, protocol, 1, 0, 2, (2, 2)) });
        if matches!(result, Some(Err(_))) {
            kt_assert_eq!(owner.state(), State::Busy);
            let effects = io.effects;
            kt_assert_eq!(
                ready(owner.notify(&mut io, None)),
                Some(Err(rfk::Error::Terminal))
            );
            kt_assert_eq!(io.effects, effects);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_wlan_source_owner_program_notifications_and_terminal_drop
);
