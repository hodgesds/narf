// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual source controller/peer, H2C envelopes/C2H parser and PS registers.
//! Inert hardware replaces MMIO, never constructs Native's OrdinaryGrant.
use super::*;
use crate::rtw89::{
    rx_packet::C2h,
    station_control::{self, Controller},
};
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::native_emission::ProviderLifetime;
const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
const AP: [u8; 6] = [2, 3, 5, 7, 11, 13];
pub(in crate::rtw89) fn peer() -> (Admission, Peer) {
    let admission = Admission::new();
    let mut io = station_control::tests::Model::new();
    let mut controller = Controller::new(&station_control::tests::factory(false)).unwrap();
    narf_scheduler::block_on(controller.initialize(&mut io, &admission)).unwrap();
    let peer = narf_scheduler::block_on(controller.prepare_peer(&mut io, AP, &admission)).unwrap();
    narf_scheduler::block_on(controller.commit_peer(&mut io, AP, 42, false, &admission)).unwrap();
    (admission, peer)
}
struct Current;
impl<T, R: narf_capabilities::Rights> CapOp<T, R> for Current {
    type Output = ();
    fn execute(self, _: &Cap<T, R>) -> Result<(), CapError> {
        Ok(())
    }
}
pub(in crate::rtw89) struct Firmware {
    pub(in crate::rtw89) clock: u64,
    device: Cap<narf_bus::BusDeviceCap, Write>,
    program: Cap<narf_firmware::FirmwareBlob, Read>,
    packets: BTreeMap<u8, Vec<u8>>,
    pub(in crate::rtw89) h2c: Vec<Vec<u8>>,
    pub(in crate::rtw89) line: Option<Arc<crate::rtw89::irq::Line>>,
    pub(in crate::rtw89) pending_probe: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    pub(in crate::rtw89) on_coex_off: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(in crate::rtw89) before_enter: Option<Arc<dyn Fn() + Send + Sync>>,
    sequence: u8,
    rpwm: u16,
    cpwm: u16,
    response: u8,
    deep: bool,
    ps: bool,
    pub(in crate::rtw89) restored: u32,
    pub(in crate::rtw89) idle: bool,
    pub(in crate::rtw89) blocked: bool,
    pub(in crate::rtw89) pending_native: bool,
    pub(in crate::rtw89) resets: u32,
    coex_transitions: u32,
    hold: bool,
    hold_delay: bool,
    no_deep: bool,
    stale_cpwm: u8,
    revoke_delay: bool,
    wrong_packet: bool,
}
struct Invoke<F>(F);
impl<T, R: narf_capabilities::Rights, V, F: FnOnce() -> Result<V, power::Error>> CapOp<T, R>
    for Invoke<F>
{
    type Output = Result<V, power::Error>;
    fn execute(self, _: &Cap<T, R>) -> Result<Self::Output, CapError> {
        Ok((self.0)())
    }
}
impl Firmware {
    fn pending_work(&self) -> bool {
        self.pending_native || self.pending_probe.as_ref().is_some_and(|probe| probe())
    }
    fn with<V>(
        &mut self,
        binding: &Binding,
        operation: impl FnOnce(&mut Self) -> Result<V, power::Error>,
    ) -> Result<V, power::Error> {
        self.current(binding)?;
        let device = self.device;
        let program = self.program;
        binding.run(|| {
            device
                .invoke(Invoke(|| {
                    program
                        .invoke(Invoke(|| operation(self)))
                        .map_err(|_| power::Error::Access)?
                }))
                .map_err(|_| power::Error::Access)?
        })
    }
    pub(in crate::rtw89) fn new() -> Self {
        Self {
            clock: 0,
            device: Cap::bootstrap(),
            program: Cap::bootstrap(),
            packets: BTreeMap::new(),
            h2c: Vec::new(),
            line: None,
            pending_probe: None,
            on_coex_off: None,
            before_enter: None,
            sequence: 0,
            rpwm: 0,
            cpwm: 0,
            response: 0,
            deep: false,
            ps: false,
            restored: 0,
            idle: true,
            blocked: false,
            pending_native: false,
            resets: 0,
            coex_transitions: 0,
            hold: false,
            hold_delay: false,
            no_deep: false,
            stale_cpwm: 0,
            revoke_delay: false,
            wrong_packet: false,
        }
    }
    fn publish(
        &mut self,
        binding: &Binding,
        class: u8,
        function: u8,
        body: &[u8],
        recv: bool,
        done: bool,
    ) -> Result<(), power::Error> {
        self.current(binding)?;
        let sequence = self.sequence;
        self.sequence = self.sequence.checked_add(1).ok_or(power::Error::Terminal)?;
        let mut bytes = vec![0; 8 + body.len()];
        crate::rtw89::txrx::encode_h2c_header(
            1,
            class,
            function,
            sequence,
            body.len() as u16,
            recv,
            done,
            &mut bytes,
        )
        .ok_or(power::Error::Access)?;
        bytes[8..].copy_from_slice(body);
        // Publication is inside both original actual model capabilities,
        // after the separately retained original source/peer fixed fence.
        self.with(binding, |firmware| {
            firmware.h2c.push(bytes);
            Ok(())
        })?;
        if done || recv {
            if let Some(line) = self.line.as_ref() {
                line.raise();
            }
        }
        for ack in [false, true] {
            if ack && !done || !ack && !recv {
                continue;
            }
            let mut raw = vec![0; 12];
            raw[0..4].copy_from_slice(&(1u32 | u32::from(ack) << 8).to_le_bytes());
            raw[4..8].copy_from_slice(&12u32.to_le_bytes());
            let word = 1u32
                | u32::from(class) << 2
                | u32::from(function) << 8
                | u32::from(sequence) << (if ack { 24 } else { 16 });
            raw[8..12].copy_from_slice(&word.to_le_bytes());
            let parsed = C2h::parse(raw)
                .map_err(|_| power::Error::Access)?
                .ack()
                .map_err(|_| power::Error::Access)?
                .ok_or(power::Error::Access)?;
            if (
                parsed.category,
                parsed.class,
                parsed.function,
                parsed.sequence,
            ) != (1, class, function, sequence)
                || parsed.result != ack.then_some(0)
            {
                return Err(power::Error::Access);
            }
        }
        Ok(())
    }
    fn response(id: u8, op: u8) -> Vec<u8> {
        let mut raw = vec![0; 12];
        raw[0..4].copy_from_slice(&(1u32 | 1 << 2 | 2 << 8).to_le_bytes());
        raw[4..8].copy_from_slice(&12u32.to_le_bytes());
        // Linux uses nonzero pkt_len for ADD and DEL; deliberately not an
        // echo of the16/24/26-byte host template length.
        raw[8..12].copy_from_slice(&(u32::from(id) | u32::from(op) << 8 | 1 << 16).to_le_bytes());
        C2h::parse(raw).unwrap().bytes
    }
}
// SAFETY: inert exclusive model, actual cap/current invocations, exact
// source envelopes and register ownership. It never touches real hardware.
unsafe impl Io for Firmware {
    fn block(&mut self, blocked: bool) {
        self.blocked = blocked;
    }
    async fn coex(&mut self, binding: &Binding, enter: bool) -> Result<(), power::Error> {
        self.current(binding)?;
        if self.deep || !enter && self.ps {
            return Err(power::Error::Access);
        }
        self.coex_transitions += 1;
        self.clock += 1000;
        if let Some(line) = self.line.as_ref() {
            line.raise();
        }
        if enter {
            if let Some(effect) = self.on_coex_off.take() {
                effect();
            }
        }
        Ok(())
    }
    async fn reset(&mut self) -> Result<(), power::Error> {
        self.device
            .invoke(Current)
            .map_err(|_| power::Error::Access)?;
        self.blocked = true;
        self.resets += 1;
        // Model terminal retention, not a manufactured native FLR fence.
        Ok(())
    }
    fn current(&mut self, binding: &Binding) -> Result<(), power::Error> {
        binding.current()?;
        self.device
            .invoke(Current)
            .map_err(|_| power::Error::Access)?;
        self.program
            .invoke(Current)
            .map_err(|_| power::Error::Access)
    }
    fn pending(&mut self, binding: &Binding) -> Result<bool, power::Error> {
        self.current(binding)?;
        Ok(self.pending_work())
    }
    fn idle(&mut self, binding: &Binding) -> Result<bool, power::Error> {
        self.current(binding)?;
        Ok(self.idle && !self.deep && !self.ps && !self.pending_work())
    }
    async fn packet(
        &mut self,
        binding: &Binding,
        body: &[u8],
        id: u8,
        operation: u8,
    ) -> Result<Vec<u8>, power::Error> {
        self.publish(binding, 9, 1, body, true, true)?;
        if self.hold {
            core::future::pending::<()>().await;
        }
        self.current(binding)?;
        if body.len() < 4 || body[0] != id || body[1] != operation || self.deep {
            return Err(power::Error::Access);
        }
        match operation {
            0 => {
                let length = u16::from_le_bytes([body[2], body[3]]) as usize;
                if body.len() != length + 4 || self.packets.insert(id, body[4..].to_vec()).is_some()
                {
                    return Err(power::Error::Access);
                }
            }
            1 => {
                if self.ps || self.packets.remove(&id).is_none() {
                    return Err(power::Error::Access);
                }
            }
            _ => return Err(power::Error::Access),
        }
        Ok(Self::response(
            if self.wrong_packet {
                id.wrapping_add(1)
            } else {
                id
            },
            operation,
        ))
    }
    async fn command(
        &mut self,
        binding: &Binding,
        class: u8,
        function: u8,
        body: &[u8],
        done: bool,
    ) -> Result<(), power::Error> {
        if (class, function) == (2, 0) && body == lps_wire::parameters(true) {
            // Inert actual credit-wait/publication seam: late raw native work
            // must deny ENTER before the protected H2C publication below.
            if let Some(effect) = self.before_enter.take() {
                effect();
            }
            if self.pending_work() {
                return Err(power::Error::Busy);
            }
        }
        self.publish(binding, class, function, body, false, done)?;
        match (class, function) {
            (0, 1) => {
                if !done
                    || body.len() != 6
                    || body[0] != 0
                    || [1, 5].iter().any(|i| body[*i] != 255)
                    || body[2..5].iter().any(|id| !self.packets.contains_key(id))
                {
                    return Err(power::Error::Access);
                }
            }
            (2, 0) => {
                if body == lps_wire::parameters(true) && !done {
                    self.ps = true;
                } else if body == lps_wire::parameters(false)
                    && done
                    && !self.deep
                    && self.restored != 0
                {
                    self.ps = false;
                } else {
                    return Err(power::Error::Access);
                }
            }
            _ => return Err(power::Error::Access),
        }
        Ok(())
    }
    fn read16(&mut self, binding: &Binding, address: u32) -> Result<u16, power::Error> {
        self.current(binding)?;
        match address {
            0x1e4 => Ok(self.rpwm),
            0x8170 => {
                if self.stale_cpwm != 0 {
                    self.stale_cpwm -= 1;
                    Ok(self.cpwm ^ 0x1000)
                } else {
                    Ok(self.cpwm)
                }
            }
            _ => Err(power::Error::Access),
        }
    }
    fn read32(&mut self, binding: &Binding, address: u32) -> Result<u32, power::Error> {
        self.current(binding)?;
        match address {
            0x1e8 => Ok(u32::from(self.deep) << 31),
            0xca0c => Ok(if self.ps { 0xe } else { 0 }),
            _ => Err(power::Error::Access),
        }
    }
    fn write16(&mut self, binding: &Binding, address: u32, value: u16) -> Result<(), power::Error> {
        self.with(binding, |this| {
            if address != 0x10c0 || value & 0x8000 == this.rpwm & 0x8000 {
                return Err(power::Error::Access);
            }
            let state = value & 7;
            if state == 5 {
                if !this.ps || value & 0x4000 != 0 {
                    return Err(power::Error::Access);
                }
                this.deep = !this.no_deep;
            } else if state == 0 {
                if value & 0x4000 == 0 {
                    return Err(power::Error::Access);
                }
                this.deep = false;
                this.response = (this.response + 1) & 3;
                this.cpwm = ((value >> 12) & 3) << 8 | u16::from(this.response) << 12;
            } else {
                return Err(power::Error::Access);
            }
            this.rpwm = value;
            Ok(())
        })
    }
    fn now_us(&self) -> u64 {
        self.clock
    }
    async fn delay_us(&mut self, us: u64) {
        self.clock += us;
        if self.hold_delay {
            core::future::pending::<()>().await;
        }
        if self.revoke_delay {
            self.program.revoke();
        }
    }
    fn restore(&mut self, binding: &Binding) -> Result<(), power::Error> {
        self.current(binding)?;
        if self.deep || !self.ps {
            return Err(power::Error::Access);
        }
        self.restored += 1;
        Ok(())
    }
}
fn setup(namespace: &mut Namespace) -> (Owner, Firmware, ProviderLifetime) {
    let (admission, peer) = self::peer();
    let source = ProviderLifetime::new();
    let binding = Binding::new(peer, admission, source.observe(), 1).unwrap();
    let owner = Owner::prepare(
        namespace,
        Profile::for_version([0, 29, 29, 15]).unwrap(),
        binding,
        42,
        true,
    )
    .unwrap();
    (owner, Firmware::new(), source)
}
fn smoke_rtw89_lps_native_templates_clock_receipts_restore_and_no_data_counters() -> TestResult {
    #[cfg(feature = "kernel-test")]
    if let Err(error) = crate::rtw89::command_native::tests::lps_tests::run() {
        return TestResult::Fail(error);
    }

    let mut namespace = Namespace::after_firmware(1).unwrap();
    let (mut owner, mut hw, _source) = setup(&mut namespace);
    narf_scheduler::block_on(owner.install(&mut hw)).unwrap();
    let expected = lps_wire::templates(OWN, AP, 42, true).unwrap();
    if hw.packets.values().cloned().collect::<Vec<_>>() != expected || !owner.active() {
        return TestResult::Fail("actual PS templates/GENERAL receipts absent");
    }
    hw.idle = false;
    if narf_scheduler::block_on(owner.enter(&mut hw)) != Ok(false) || hw.ps {
        return TestResult::Fail("PS entered with original native work outstanding");
    }
    hw.idle = true;
    narf_scheduler::block_on(owner.enter(&mut hw)).unwrap();
    if owner.phase() != Phase::Deep || !hw.deep || !hw.ps {
        return TestResult::Fail("LPS H2C alone conferred actual deep state");
    }
    hw.stale_cpwm = 2;
    narf_scheduler::block_on(owner.wake(&mut hw)).unwrap();
    if !owner.active()
        || hw.deep
        || hw.ps
        || hw.restored != 1
        || hw.clock != 2300
        || hw.coex_transitions != 2
    {
        return TestResult::Fail("stale CPWM/restore/leave receipts opened ordinary owner");
    }
    narf_scheduler::block_on(owner.remove(&mut hw)).unwrap();
    if !hw.packets.is_empty() || owner.phase() != Phase::Removed {
        return TestResult::Fail("actual non-echo DEL response failed template cleanup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/runtime_sleep",
    smoke_rtw89_lps_native_templates_clock_receipts_restore_and_no_data_counters
);
fn smoke_rtw89_lps_native_current_source_loss_never_emits_null_wake() -> TestResult {
    let mut namespace = Namespace::after_firmware(1).unwrap();
    let (mut owner, mut hw, source) = setup(&mut namespace);
    narf_scheduler::block_on(owner.install(&mut hw)).unwrap();
    narf_scheduler::block_on(owner.enter(&mut hw)).unwrap();
    let count = hw.h2c.len();
    source.retire().notify();
    if narf_scheduler::block_on(owner.wake(&mut hw)).is_ok()
        || hw.h2c.len() != count
        || !hw.deep
        || owner.active()
    {
        return TestResult::Fail("retired original UP source borrowed NULL wake permission");
    }
    let replacement = ProviderLifetime::new();
    if owner.current().is_ok() || !replacement.observe().current() {
        return TestResult::Fail("replacement metadata revived old source");
    }
    let mut namespace = Namespace::after_firmware(2).unwrap();
    let (mut owner, mut hw, _source) = setup(&mut namespace);
    narf_scheduler::block_on(owner.install(&mut hw)).unwrap();
    narf_scheduler::block_on(owner.enter(&mut hw)).unwrap();
    let calls = hw.h2c.len();
    hw.stale_cpwm = 2;
    hw.revoke_delay = true;
    if narf_scheduler::block_on(owner.wake(&mut hw)).is_ok()
        || hw.h2c.len() != calls
        || hw.restored != 0
        || owner.active()
    {
        return TestResult::Fail("source loss at real CPWM wait escaped NULL/restore fence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/runtime_sleep",
    smoke_rtw89_lps_native_current_source_loss_never_emits_null_wake
);
fn smoke_rtw89_lps_native_dropped_packet_receipt_retains_closed_owner_ids() -> TestResult {
    let mut namespace = Namespace::after_firmware(1).unwrap();
    let (mut owner, mut hw, source) = setup(&mut namespace);
    hw.hold = true;
    let mut future = Box::pin(owner.install(&mut hw));
    if !matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return TestResult::Fail("offload missing held native receipt");
    }
    drop(future);
    if owner.active()
        || owner.phase() != Phase::Installing
        || owner.packets.pending() != Some((0, 0))
    {
        return TestResult::Fail("dropped ADD returned unknown owner/packet id");
    }
    let (admission, peer) = self::peer();
    let next = namespace.reserve(peer, 2, 42, false).unwrap();
    let mut next = next;
    if next.begin_add().unwrap()[0] != 3 || !source.observe().current() {
        return TestResult::Fail("uncertain template identities were recycled");
    }
    if Binding::new(owner.binding.peer.clone(), admission, source.observe(), 0).is_ok() {
        return TestResult::Fail("zero association metadata admitted");
    }
    let (admission, peer) = self::peer();
    let source = ProviderLifetime::new();
    let mut manager =
        Manager::after_firmware(Profile::for_version([0, 29, 29, 15]).unwrap()).unwrap();
    manager.committed(42).unwrap();
    let mut hw = Firmware::new();
    narf_scheduler::block_on(manager.service(
        &mut hw,
        Some(peer.clone()),
        &admission,
        Intent {
            identity: Some(source.observe()),
            enabled: true,
            idle: true,
            force: false,
        },
    ))
    .unwrap();
    let calls = hw.h2c.len();
    hw.stale_cpwm = 255;
    hw.hold_delay = true;
    let mut future = Box::pin(manager.service(
        &mut hw,
        Some(peer.clone()),
        &admission,
        Intent {
            identity: Some(source.observe()),
            enabled: true,
            idle: false,
            force: true,
        },
    ));
    if !matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return TestResult::Fail("wake skipped actual held CPWM receipt");
    }
    drop(future);
    hw.hold_delay = false;
    if !hw.blocked
        || manager.owner.as_ref().unwrap().phase() != Phase::Leaving
        || hw.h2c.len() != calls
    {
        return TestResult::Fail("dropped RPWM wait released ordinary/NULL ownership");
    }
    if narf_scheduler::block_on(manager.service(
        &mut hw,
        Some(peer),
        &admission,
        Intent {
            identity: Some(source.observe()),
            enabled: false,
            idle: false,
            force: true,
        },
    ))
    .is_ok()
        || hw.resets != 1
        || hw.h2c.len() != calls
        || !hw.blocked
    {
        return TestResult::Fail("cancelled wake resumed instead of device-only terminal cleanup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/runtime_sleep",
    smoke_rtw89_lps_native_dropped_packet_receipt_retains_closed_owner_ids
);
fn smoke_rtw89_lps_native_retry_budget_and_failed_poll_do_not_consume_response() -> TestResult {
    let mut namespace = Namespace::after_firmware(1).unwrap();
    let (mut owner, mut hw, _source) = setup(&mut namespace);
    narf_scheduler::block_on(owner.install(&mut hw)).unwrap();
    hw.no_deep = true;
    if narf_scheduler::block_on(owner.enter(&mut hw)) != Err(power::Error::Timeout)
        || hw.clock != 46_000
        || owner.active()
        || owner.phase() != Phase::Entering
    {
        return TestResult::Fail("unbounded/false deep receipt reopened native station");
    }
    let mut namespace = Namespace::after_firmware(3).unwrap();
    let (mut wrong, mut bad_hw, _bad_source) = setup(&mut namespace);
    bad_hw.wrong_packet = true;
    if narf_scheduler::block_on(wrong.install(&mut bad_hw)).is_ok() || wrong.active() {
        return TestResult::Fail("wrong native offload C2H id became template readiness");
    }
    let mut counters = lps_wire::Counters::default();
    let enter = counters.prepare(0, 5).unwrap();
    assert!(counters.published(enter));
    assert!(counters.completed(enter, 1 << 31, 0));
    let leave = counters.prepare(enter.wire, 0).unwrap();
    assert!(counters.published(leave));
    for _ in 0..8 {
        if counters.completed(leave, 0, 0) {
            return TestResult::Fail("wrong atomic CPWM receipt accepted");
        }
    }
    if !counters.completed(leave, 0, 0x1200) {
        return TestResult::Fail("failed polls consumed original response counter");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/runtime_sleep",
    smoke_rtw89_lps_native_retry_budget_and_failed_poll_do_not_consume_response
);
