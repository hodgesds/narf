// SPDX-License-Identifier: GPL-2.0-or-later
//! Independent DBI/MDIO device model. Only hardware config is inert;
//! all production ASPM command/poll/readback code executes unchanged.
use super::*;
use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    Byte(u16, u8),
    Word(u16, u16),
    Dword(u16, u32),
}
struct State {
    registers: [u8; 0x400],
    config: [u32; 2],
    address: u16,
    mdio: [u16; 32],
    writes: Vec<Write>,
}
pub(crate) struct Model {
    state: IrqSafeSpinLock<State>,
    configured: AtomicBool,
    pub(crate) control: AtomicU16,
    pub(crate) parent: AtomicU16,
    live: AtomicBool,
    hold: AtomicBool,
    ignore: AtomicBool,
    revoke_on_wait: AtomicBool,
    waits: AtomicUsize,
    pub(crate) withdraw_parent_on_wait: AtomicBool,
}
impl Model {
    pub(crate) fn new() -> Self {
        Self {
            configured: AtomicBool::new(false),
            control: AtomicU16::new(0x43),
            parent: AtomicU16::new(0x43),
            state: IrqSafeSpinLock::new(State {
                registers: [0; 0x400],
                config: [0x12345678, 0xa5000005],
                address: 0,
                mdio: [0; 32],
                writes: Vec::new(),
            }),
            live: AtomicBool::new(true),
            hold: AtomicBool::new(false),
            ignore: AtomicBool::new(false),
            revoke_on_wait: AtomicBool::new(false),
            waits: AtomicUsize::new(0),
            withdraw_parent_on_wait: AtomicBool::new(false),
        }
    }
    pub(crate) fn fresh_owner(&self) {
        self.configured.store(false, Ordering::Release);
    }
    fn current(&self) -> Result<(), Error> {
        if self.live.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(Error::Access)
        }
    }
}
#[async_trait::async_trait]
impl Io for Model {
    fn write16(&self, reg: u16, value: u16) -> Result<(), Error> {
        self.current()?;
        let mut state = self.state.lock();
        state.writes.push(Write::Word(reg, value));
        state.registers[usize::from(reg)..usize::from(reg) + 2]
            .copy_from_slice(&value.to_le_bytes());
        if reg == 0x350 {
            state.address = value;
        }
        Ok(())
    }
    fn read16(&self, reg: u16) -> Result<u16, Error> {
        self.current()?;
        let state = self.state.lock();
        Ok(u16::from_le_bytes(
            state.registers[usize::from(reg)..usize::from(reg) + 2]
                .try_into()
                .unwrap(),
        ))
    }
    fn read8(&self, reg: u16) -> Result<u8, Error> {
        self.current()?;
        Ok(self.state.lock().registers[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, Error> {
        self.current()?;
        let state = self.state.lock();
        Ok(u32::from_le_bytes(
            state.registers[usize::from(reg)..usize::from(reg) + 4]
                .try_into()
                .unwrap(),
        ))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error> {
        self.current()?;
        let mut state = self.state.lock();
        state.writes.push(Write::Byte(reg, value));
        state.registers[usize::from(reg)] = value;
        if reg == 0x352 && !self.hold.load(Ordering::Acquire) {
            let index = match state.address & 0xfff {
                0x70c => 0,
                0x718 => 1,
                _ => return Err(Error::Gate),
            };
            match value {
                2 => {
                    let value = state.config[index];
                    state.registers[0x34c..0x350].copy_from_slice(&value.to_le_bytes());
                }
                1 if state.address & 0xf000 != 0 => {
                    if !self.ignore.load(Ordering::Acquire) {
                        let mut bytes = state.config[index].to_le_bytes();
                        for (lane, byte) in bytes.iter_mut().enumerate() {
                            if state.address & (1 << (lane + 12)) != 0 {
                                *byte = state.registers[0x348 + lane];
                            }
                        }
                        state.config[index] = u32::from_le_bytes(bytes);
                    }
                }
                _ => return Err(Error::Gate),
            }
            state.registers[0x352] = 0;
        }
        if reg == 0x358 && !self.hold.load(Ordering::Acquire) {
            let index = (value & 0x1f) as usize;
            if value & 0x40 != 0 {
                let read = state.mdio[index].to_le_bytes();
                state.registers[0x356..0x358].copy_from_slice(&read);
            } else if value & 0x20 != 0 && !self.ignore.load(Ordering::Acquire) {
                state.mdio[index] =
                    u16::from_le_bytes(state.registers[0x354..0x356].try_into().unwrap());
            }
            state.registers[0x358] = value & 0x1f;
        }
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error> {
        self.current()?;
        let mut state = self.state.lock();
        state.writes.push(Write::Dword(reg, value));
        state.registers[usize::from(reg)..usize::from(reg) + 4]
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write_bytes(&self, _: u16, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn delay_us(&self, _: u64) {
        self.waits.fetch_add(1, Ordering::AcqRel);
        if self.withdraw_parent_on_wait.load(Ordering::Acquire) {
            self.parent.store(0x40, Ordering::Release);
        }
        if self.revoke_on_wait.load(Ordering::Acquire) {
            self.live.store(false, Ordering::Release);
        }
        let mut once = false;
        core::future::poll_fn(|cx| {
            if once {
                Poll::Ready(())
            } else {
                once = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    }
}
impl Port for Model {}
fn complete<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    for _ in 0..128 {
        if let Poll::Ready(result) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return result;
        }
    }
    panic!("ASPM bounded fixture did not complete");
}
fn smoke_rtl8188ee_aspm_actual_dbi_mdio_and_current_parent_policy() -> TestResult {
    let model = Model::new();
    if complete(prepare(&model)).is_err() {
        return TestResult::Fail("EE actual DBI/MDIO ASPM preparation failed");
    }
    let state = model.state.lock();
    if state.config != [0x92345678, 0xa5001805]
        || state.writes[..2] != [Write::Word(0x354, 0x8104), Write::Word(0x358, 0x24)]
        || state
            .writes
            .iter()
            .filter(|entry| matches!(entry, Write::Dword(0x348, _)))
            .count()
            != 2
    {
        return TestResult::Fail(
            "EE ASPM native internal writes differ from literal Linux sequence",
        );
    }
    drop(state);
    for (caps, parent, enabled, expected) in [
        (0xc00 | 1 << 18, Some(0x43), true, 0x103),
        (0x800, Some(0x43), true, 2),
        (0xc00 | 1 << 18, Some(0x42), true, 0x102),
        (0xc00 | 1 << 18, Some(0x40), true, 0),
        (0xc00 | 1 << 18, None, true, 0),
        (0xc00 | 1 << 18, Some(0x43), false, 0),
    ] {
        if policy(caps, parent, enabled) != expected {
            return TestResult::Fail("EE endpoint ASPM exceeded actual parent/capability policy");
        }
    }
    let model = Model::new();
    model.withdraw_parent_on_wait.store(true, Ordering::Release);
    if complete(configure(&model, true)).is_err() || model.control.load(Ordering::Acquire) != 0x40 {
        return TestResult::Fail(
            "EE stale parent snapshot survived the real cooperative preparation wait",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_rtl8188ee_aspm_actual_dbi_mdio_and_current_parent_policy
);
fn smoke_rtl8188ee_aspm_timeout_readback_and_source_loss_fail_before_ready() -> TestResult {
    for revoked in [false, true] {
        let model = Model::new();
        model.hold.store(true, Ordering::Release);
        model.revoke_on_wait.store(revoked, Ordering::Release);
        if complete(prepare(&model))
            != Err(if revoked {
                Error::Access
            } else {
                Error::Deadline
            })
            || model.state.lock().config != [0x12345678, 0xa5000005]
        {
            return TestResult::Fail("EE missing DBI/source receipt became ASPM readiness");
        }
    }
    let model = Model::new();
    model.ignore.store(true, Ordering::Release);
    if complete(prepare(&model)) != Err(Error::Gate) {
        return TestResult::Fail("EE ignored DBI writes became ASPM readiness");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_rtl8188ee_aspm_timeout_readback_and_source_loss_fail_before_ready
);

impl PolicyPort for Model {
    fn desired(&self, enabled: bool) -> Result<Option<u16>, Error> {
        self.current()?;
        Ok(Some(policy(
            0xc00 | (1 << 18),
            Some(self.parent.load(Ordering::Acquire)),
            enabled,
        )))
    }
    fn control(&self, desired: u16) -> Result<(), Error> {
        self.current()?;
        let before = self.control.load(Ordering::Acquire);
        self.control
            .store((before & !CONTROL_MASK) | desired, Ordering::Release);
        Ok(())
    }
    fn prepared(&self) -> &AtomicBool {
        &self.configured
    }
}

fn smoke_ae_aspm_own_byte_program_and_parent_policy() -> TestResult {
    let model = Model::new();
    if complete(configure_for(&model, Profile::Rtl8723ae, true)).is_err()
        || model.control.load(Ordering::Acquire) != 0x143
        || !model.configured.load(Ordering::Acquire)
    {
        return TestResult::Fail("AE source internal byte program did not precede endpoint policy");
    }
    let state = model.state.lock();
    if state.config != [0x93345678, 0xa5001b05]
        || state.writes[..6]
            != [
                Write::Byte(0x34b, 0x93),
                Write::Word(0x350, 0x870c),
                Write::Byte(0x352, 1),
                Write::Byte(0x349, 0x1b),
                Write::Word(0x350, 0x2718),
                Write::Byte(0x352, 1),
            ]
        || state
            .writes
            .iter()
            .any(|w| matches!(w, Write::Word(0x354 | 0x358, _) | Write::Dword(0x348, _)))
    {
        return TestResult::Fail("AE borrowed another chip's MDIO or full-dword program");
    }
    drop(state);
    let model = Model::new();
    model.withdraw_parent_on_wait.store(true, Ordering::Release);
    if complete(configure_for(&model, Profile::Rtl8723ae, true)).is_err()
        || model.control.load(Ordering::Acquire) != 0x40
    {
        return TestResult::Fail("AE endpoint retained policy withdrawn during wait");
    }
    let model = Model::new();
    if complete(configure_for(&model, Profile::Rtl8723ae, false)).is_err()
        || !model.state.lock().writes.is_empty()
        || model.configured.load(Ordering::Acquire)
    {
        return TestResult::Fail("AE disabled link performed a backdoor program");
    }
    TestResult::Pass
}
fn smoke_ae_aspm_incomplete_or_revoked_program_never_enables_endpoint() -> TestResult {
    for mode in 0..4 {
        let model = Box::new(Model::new());
        model.control.store(0x40, Ordering::Release);
        match mode {
            0 => model.ignore.store(true, Ordering::Release),
            1 => model.hold.store(true, Ordering::Release),
            2 => {
                model.hold.store(true, Ordering::Release);
                model.revoke_on_wait.store(true, Ordering::Release);
            }
            _ => {
                model.hold.store(true, Ordering::Release);
                {
                    let mut work = pin!(configure_for(&*model, Profile::Rtl8723ae, true));
                    if !work
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                    {
                        return TestResult::Fail("AE cancellation fixture never waited");
                    }
                }
                if model.control.load(Ordering::Acquire) != 0x40
                    || model.configured.load(Ordering::Acquire)
                {
                    return TestResult::Fail("AE dropped DBI wait enabled the endpoint");
                }
                continue;
            }
        }
        if complete(configure_for(&*model, Profile::Rtl8723ae, true)).is_ok()
            || model.control.load(Ordering::Acquire) != 0x40
            || model.configured.load(Ordering::Acquire)
        {
            return TestResult::Fail("AE missing DBI/readback/current authority enabled endpoint");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_ae_aspm_own_byte_program_and_parent_policy
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_ae_aspm_incomplete_or_revoked_program_never_enables_endpoint
);

fn smoke_be_de_aspm_exact_internal_program_before_parent_bounded_enable() -> TestResult {
    for profile in [Profile::Rtl8723be, Profile::Rtl8192de] {
        let model = Model::new();
        if complete(configure_for(&model, profile, true)).is_err()
            || model.control.load(Ordering::Acquire) != 0x143
            || !model.configured.load(Ordering::Acquire)
        {
            return TestResult::Fail(
                "BE/DE internal program did not authorize bounded endpoint enable",
            );
        }
        let state = model.state.lock();
        let expected = match profile {
            Profile::Rtl8723be => [0xba345678, 0xa5001805],
            Profile::Rtl8192de => [0x93345678, 0xa5001b05],
            _ => unreachable!(),
        };
        if state.config != expected {
            return TestResult::Fail("BE latency/L0s or DE source byte program differs");
        }
        if profile == Profile::Rtl8723be {
            for (address, value) in [
                (1, 0x0663),
                (4, 0x7544),
                (6, 0xb880),
                (7, 0x4000),
                (8, 0x9003),
                (9, 0x0d03),
                (10, 0x4037),
                (11, 0x0070),
            ] {
                if state.mdio[address] != value {
                    return TestResult::Fail("BE exact ePHY compatibility words missing");
                }
            }
        } else if state
            .writes
            .iter()
            .any(|write| matches!(write, Write::Word(0x354, _)))
        {
            return TestResult::Fail("DE inherited EE/BE ePHY writes");
        }
        if !state.writes.contains(&Write::Word(0x350, 0x870c))
            || !state.writes.contains(&Write::Word(0x350, 0x2718))
        {
            return TestResult::Fail("source DBI byte enables were widened");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_be_de_aspm_exact_internal_program_before_parent_bounded_enable
);

fn smoke_be_de_aspm_busy_ignored_write_and_lost_source_never_enable() -> TestResult {
    for profile in [Profile::Rtl8723be, Profile::Rtl8192de] {
        for mode in 0..3 {
            let model = Model::new();
            match mode {
                0 => model.hold.store(true, Ordering::Release),
                1 => model.ignore.store(true, Ordering::Release),
                _ => {
                    model.hold.store(true, Ordering::Release);
                    model.revoke_on_wait.store(true, Ordering::Release);
                }
            }
            if complete(configure_for(&model, profile, true)).is_ok()
                || model.control.load(Ordering::Acquire) & CONTROL_MASK != 0
                || model.configured.load(Ordering::Acquire)
            {
                return TestResult::Fail("BE/DE missing internal receipt became link readiness");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_be_de_aspm_busy_ignored_write_and_lost_source_never_enable
);

fn smoke_be_de_aspm_disabled_parent_and_postwait_withdrawal() -> TestResult {
    for profile in [Profile::Rtl8723be, Profile::Rtl8192de] {
        let model = Model::new();
        model.parent.store(0x40, Ordering::Release);
        if complete(configure_for(&model, profile, true)).is_err()
            || !model.state.lock().writes.is_empty()
            || model.control.load(Ordering::Acquire) != 0x40
        {
            return TestResult::Fail("disabled parent still programmed/enabled endpoint");
        }
        model.parent.store(0x43, Ordering::Release);
        model.withdraw_parent_on_wait.store(true, Ordering::Release);
        if complete(configure_for(&model, profile, true)).is_err()
            || model.control.load(Ordering::Acquire) != 0x40
        {
            return TestResult::Fail("BE/DE reused parent policy across wait");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_be_de_aspm_disabled_parent_and_postwait_withdrawal
);

fn smoke_be_de_aspm_cancelled_internal_wait_keeps_endpoint_off() -> TestResult {
    for profile in [Profile::Rtl8723be, Profile::Rtl8192de] {
        let model = Model::new();
        model.hold.store(true, Ordering::Release);
        {
            let work = configure_for(&model, profile, true);
            let mut work = pin!(work);
            if !work
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
            {
                return TestResult::Fail("BE/DE native internal wait did not pend");
            }
        }
        if model.control.load(Ordering::Acquire) & CONTROL_MASK != 0
            || model.configured.load(Ordering::Acquire)
        {
            return TestResult::Fail("cancelled BE/DE internal wait published preparation");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_be_de_aspm_cancelled_internal_wait_keeps_endpoint_off
);
fn smoke_rtl8188ee_aspm_cancelled_native_wait_does_not_enable_endpoint() -> TestResult {
    let model = Model::new();
    model.hold.store(true, Ordering::Release);
    let mut work = alloc::boxed::Box::pin(configure(&model, true));
    if work
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    {
        return TestResult::Fail("EE held DBI command did not preserve a cooperative wait");
    }
    drop(work);
    if model.configured.load(Ordering::Acquire)
        || model.control.load(Ordering::Acquire) & CONTROL_MASK != 0
    {
        return TestResult::Fail("EE abandoned bus preparation enabled unproven endpoint entry");
    }
    model.live.store(false, Ordering::Release);
    if complete(configure(&model, true)) != Err(Error::Access) {
        return TestResult::Fail("EE revoked bus source revived abandoned ASPM work");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/aspm",
    smoke_rtl8188ee_aspm_cancelled_native_wait_does_not_enable_endpoint
);
