use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_capabilities::{object_table, CapKind, Rights};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");

#[derive(Clone, Copy, Debug)]
struct Access {
    at: u64,
    offset: u16,
    width: u16,
    write: bool,
    value: u32,
}
struct Clock {
    now: AtomicU64,
    release: AtomicBool,
}
struct Model {
    config: Vec<u8>,
    original: Vec<u8>,
    binding: Binding,
    authority: Cap<BusDeviceCap, Write>,
    clock: Arc<Clock>,
    log: Vec<Access>,
    delays: Vec<u64>,
    trigger: Option<u64>,
    triggers: usize,
    pending_until: u64,
    ready_delay: u64,
    hold_quarantine: bool,
    ignore_bar: Option<u16>,
    swap_identity: bool,
    stuck_flr: bool,
    quiet_violation: bool,
}
fn authority() -> Cap<BusDeviceCap, Write> {
    let (index, generation) = object_table::register(CapKind::BusDevice);
    // SAFETY: fresh exact typed fixture object and Write rights.
    unsafe {
        Cap::mint(CapSlot::new(
            generation,
            index,
            Write::BITS,
            CapKind::BusDevice as u32,
        ))
    }
}
fn device() -> BusDevice {
    let addr = narf_bus::PcieAddr::new(0, 2, 3, 0);
    BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor: 0x10ec,
            device: 0xb852,
            class: 0x028000,
            subsystem_vendor: 0x10ec,
            subsystem_id: 0x1234,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0x2000),
        },
    }
}
impl Model {
    fn new() -> Self {
        let authority = authority();
        let mut model = Self {
            config: vec![0; 256],
            original: Vec::new(),
            binding: Binding::new(&device(), &authority).unwrap(),
            authority,
            clock: Arc::new(Clock {
                now: AtomicU64::new(0),
                release: AtomicBool::new(false),
            }),
            log: Vec::new(),
            delays: Vec::new(),
            trigger: None,
            triggers: 0,
            pending_until: 0,
            ready_delay: 0,
            hold_quarantine: false,
            ignore_bar: None,
            swap_identity: false,
            stuck_flr: false,
            quiet_violation: false,
        };
        model.put32(0, 0xb852_10ec);
        model.put32(4, 0x0010_0007);
        model.put32(8, 0x0280_0005);
        model.put32(0x2c, 0x1234_10ec);
        model.put32(0x34, 0x40);
        model.put16(0x40, 0x8010); // Express -> MSI
        model.put16(0x42, 2); // PCIe2 endpoint
        model.put32(0x44, 1 << 28);
        model.put16(0x48, 0x2000);
        model.put16(0x80, 0xa005); // MSI -> MSI-X
        model.put16(0x82, 0x0181);
        model.put16(0xa0, 0x0011);
        model.put16(0xa2, 0x8000);
        for (index, value) in [4, 1, 0x8000_0004, 0, 0xc001, 0].into_iter().enumerate() {
            model.put32(0x10 + index as u16 * 4, value);
        }
        model.put32(0x30, 0x9000_0001);
        model.original = model.config.clone();
        model
    }
    fn reset(self) -> Reset<Self> {
        let binding = self.binding;
        Reset {
            io: self,
            binding,
            phase: Phase::New,
        }
    }
    fn put16(&mut self, offset: u16, value: u16) {
        self.config[offset as usize..offset as usize + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(&mut self, offset: u16, value: u32) {
        self.config[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn raw16(&self, offset: u16) -> u16 {
        u16::from_le_bytes(
            self.config[offset as usize..offset as usize + 2]
                .try_into()
                .unwrap(),
        )
    }
    fn raw32(&self, offset: u16) -> u32 {
        u32::from_le_bytes(
            self.config[offset as usize..offset as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn access(&mut self, offset: u16, width: u16, write: bool, value: u32) -> Result<(), Error> {
        let cap = self.authority;
        crate::rtw88::pci_park::invoke(&cap, || {
            let now = self.now_ms();
            if self.trigger.is_some_and(|at| now.saturating_sub(at) < 100) {
                self.quiet_violation = true;
                return Err(Error::Readback);
            }
            self.log.push(Access {
                at: now,
                offset,
                width,
                write,
                value,
            });
            Ok(())
        })
        .map_err(|_| Error::Access)?
    }
}
// SAFETY: inert config model exclusively owns its bytes; each actual modeled
// access executes under a fresh real current BusDevice epoch invocation. The
// model clock is explicit and no config access is hidden in delay/Drop.
unsafe impl Io for Model {
    fn binding(&self) -> Binding {
        self.binding
    }
    fn read16(&mut self, offset: u16) -> Result<u16, Error> {
        let value =
            if offset == 0x4a && self.trigger.is_none() && self.now_ms() < self.pending_until {
                1 << 5
            } else {
                self.raw16(offset)
            };
        self.access(offset, 2, false, u32::from(value))?;
        Ok(value)
    }
    fn read32(&mut self, offset: u16) -> Result<u32, Error> {
        let value = if offset == 4
            && self
                .trigger
                .is_some_and(|at| self.now_ms().saturating_sub(at) < 101 + self.ready_delay)
        {
            u32::MAX
        } else {
            self.raw32(offset)
        };
        self.access(offset, 4, false, value)?;
        Ok(value)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), Error> {
        self.access(offset, 2, true, u32::from(value))?;
        if offset == 0x48 && value & (1 << 15) != 0 {
            if self.raw16(4) & 7 != 0
                || self.raw16(0x82) & 1 != 0
                || self.raw16(0xa2) & (3 << 14) != 1 << 14
            {
                return Err(Error::Readback);
            }
            self.trigger = Some(self.now_ms());
            self.triggers += 1;
            self.put16(4, 0);
            self.put16(0x48, if self.stuck_flr { 1 << 15 } else { 0 });
            // Source FLR resets writable BAR/control state; immutable identity
            // and capability chain survive. Driver must restore exact BARs.
            for offset in [0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30] {
                self.put32(offset, 0);
            }
            self.put16(0x82, 0x0180);
            self.put16(0xa2, 0);
            if self.swap_identity {
                self.put32(0, 0xb85b_10ec);
            }
        } else {
            self.put16(offset, value);
        }
        Ok(())
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), Error> {
        self.access(offset, 4, true, value)?;
        if self.ignore_bar != Some(offset) {
            self.put32(offset, value);
        }
        Ok(())
    }
    fn now_ms(&self) -> u64 {
        self.clock.now.load(Ordering::Acquire)
    }
    async fn delay_ms(&mut self, ms: u64) {
        self.delays.push(ms);
        if self.hold_quarantine && ms == 101 {
            core::future::poll_fn(|cx| {
                if self.clock.release.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }
        self.clock.now.fetch_add(ms, Ordering::AcqRel);
    }
}
fn complete<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..1024 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return Some(value);
        }
    }
    None
}
fn smoke_rtw89_b_flr_real_quiet_interval_and_exact_parked_bar_restore() -> TestResult {
    let mut reset = Model::new().reset();
    let Some(Ok(fence)) = complete(reset.run()) else {
        return TestResult::Fail("actual FLR sequence did not complete");
    };
    if reset.phase() != Phase::Ready
        || reset.io.triggers != 1
        || reset.io.quiet_violation
        || reset.io.delays != [101]
        || fence.binding != reset.binding
        || reset.io.raw16(4) & (7 | 1 << 10) != 1 << 10
        || reset.io.raw16(0x82) & 1 != 0
        || reset.io.raw16(0xa2) & (3 << 14) != 1 << 14
        || reset.io.config[0x10..0x28] != reset.io.original[0x10..0x28]
        || reset.io.config[0x30..0x34] != reset.io.original[0x30..0x34]
    {
        return TestResult::Fail("FLR proof lacked minimum time, exact BARs or parked DMA/IRQ");
    }
    let trigger = reset
        .io
        .log
        .iter()
        .position(|a| a.write && a.offset == 0x48 && a.value & (1 << 15) != 0)
        .unwrap();
    if reset.io.log[trigger + 1..]
        .iter()
        .any(|a| a.at < SOURCE_QUIET_MS)
        || reset.io.log.iter().any(|a| a.width != 2 && a.width != 4)
    {
        return TestResult::Fail("config accessed before real100ms FLR quiet interval");
    }
    let restore: Vec<_> = reset.io.log[trigger + 1..]
        .iter()
        .filter(|a| a.write && (0x10..0x28).contains(&a.offset))
        .map(|a| a.offset)
        .collect();
    if restore != [0x24, 0x20, 0x1c, 0x18, 0x14, 0x10]
        || complete(reset.run()).is_none_or(|r| !matches!(r, Err(Error::Terminal)))
    {
        return TestResult::Fail("FLR replay or BAR restoration order differs from source");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_flr_real_quiet_interval_and_exact_parked_bar_restore
);

fn smoke_rtw89_b_flr_unsupported_pending_and_malformed_caps_never_trigger() -> TestResult {
    for fault in 0..5 {
        let mut model = Model::new();
        match fault {
            0 => model.put32(0x44, 0),
            1 => model.pending_until = u64::MAX,
            2 => model.put16(0xa0, 0x4011), // cycle
            3 => model.put32(0x34, 0x41),
            4 => model.binding.id.subsystem_id ^= 1,
            _ => unreachable!(),
        }
        let mut reset = model.reset();
        let Some(Err(_)) = complete(reset.run()) else {
            return TestResult::Fail("unsupported/pending/malformed FLR accepted");
        };
        if reset.phase() != Phase::Terminal || reset.io.triggers != 0 || reset.io.quiet_violation {
            return TestResult::Fail(
                "preflight/pending failure triggered FLR or granted reusable state",
            );
        }
        if fault == 1 && reset.io.delays != [100, 200, 400] {
            return TestResult::Fail("TP-pending sampling differs from Linux0/100/300/700ms");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_flr_unsupported_pending_and_malformed_caps_never_trigger
);

fn smoke_rtw89_b_flr_cancelled_quarantine_performs_no_config_or_replay() -> TestResult {
    let mut model = Model::new();
    model.hold_quarantine = true;
    let mut reset = model.reset();
    let clock = reset.io.clock.clone();
    {
        let mut future = pin!(reset.run());
        let mut context = Context::from_waker(Waker::noop());
        if !future.as_mut().poll(&mut context).is_pending() {
            return TestResult::Fail("FLR quarantine did not suspend");
        }
    }
    let before = reset.io.log.len();
    clock.now.store(1000, Ordering::Release);
    if reset.phase() != Phase::Terminal
        || reset.io.triggers != 1
        || reset.io.quiet_violation
        || !matches!(complete(reset.run()), Some(Err(Error::Terminal)))
        || reset.io.log.len() != before
        || reset
            .io
            .log
            .last()
            .is_none_or(|a| !a.write || a.offset != 0x48)
    {
        return TestResult::Fail("cancelled triggered reset accessed config or replayed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_flr_cancelled_quarantine_performs_no_config_or_replay
);

fn smoke_rtw89_b_flr_post_reset_readiness_identity_and_bar_failures_no_fence() -> TestResult {
    for fault in 0..4 {
        let mut model = Model::new();
        match fault {
            0 => model.ready_delay = 60_001,
            1 => model.swap_identity = true,
            2 => model.ignore_bar = Some(0x14),
            3 => model.stuck_flr = true,
            _ => unreachable!(),
        }
        let mut reset = model.reset();
        if !matches!(complete(reset.run()), Some(Err(_)))
            || reset.phase() != Phase::Terminal
            || reset.io.triggers != 1
            || reset.io.quiet_violation
        {
            return TestResult::Fail(
                "failed post-FLR readiness/identity/BAR/self-clear produced fence",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_flr_post_reset_readiness_identity_and_bar_failures_no_fence
);

fn smoke_rtw89_b_flr_real_epoch_revocation_and_fence_binding_are_current() -> TestResult {
    let mut model = Model::new();
    model.hold_quarantine = true;
    let mut reset = model.reset();
    let cap = reset.io.authority;
    let clock = reset.io.clock.clone();
    let result = {
        let mut future = pin!(reset.run());
        let mut context = Context::from_waker(Waker::noop());
        if !future.as_mut().poll(&mut context).is_pending() {
            return TestResult::Fail("revocation quarantine fixture");
        }
        cap.revoke();
        clock.release.store(true, Ordering::Release);
        future.as_mut().poll(&mut context)
    };
    if !matches!(result, Poll::Ready(Err(Error::Access)))
        || reset.io.quiet_violation
        || reset
            .io
            .log
            .last()
            .is_none_or(|a| !a.write || a.offset != 0x48)
    {
        return TestResult::Fail("revoked current epoch reached post-FLR config");
    }
    // Actual Native must reject before this deliberately unmapped ECAM window.
    let cap = authority();
    cap.revoke();
    // SAFETY: private exclusive unmapped fixture; current revocation must reject
    // before actual config. No live function or hardware producer exists.
    if !matches!(unsafe { Reset::claim(device(), cap) }, Err(Error::Access)) {
        return TestResult::Fail("actual revoked Native reset claim accepted");
    }
    for fault in 0..4 {
        let mut reset = Model::new().reset();
        let fence = complete(reset.run()).unwrap().unwrap();
        let mut candidate = device();
        let cap = if fault == 1 {
            let cap = reset.io.authority;
            cap.revoke();
            cap
        } else if fault == 0 {
            authority()
        } else {
            if let BusKind::Pcie { addr, cfg_phys } = &mut candidate.kind {
                if fault == 2 {
                    addr.bus += 1;
                    candidate.addr = BusAddr::Pcie(*addr);
                } else {
                    *cfg_phys = narf_memory::PhysAddr::new(0x3000);
                }
            }
            reset.io.authority
        };
        // Wrong slot or revoked exact epoch must reject BEFORE unmapped ECAM.
        if !matches!(
            super::super::startup::Startup::claim_reset(candidate, cap, fence),
            Err(super::super::startup::Error::Register(
                super::super::power::Error::Access
            ))
        ) {
            return TestResult::Fail(
                "FLR fence retargeted to another slot/epoch or skipped current invocation",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_flr_real_epoch_revocation_and_fence_binding_are_current
);

fn smoke_rtw89_b_flr_pending_and_quiet_timing_matches_extracted_linux_c() -> TestResult {
    for (scenario, expected) in PENDING_READ_TIMES.iter().enumerate() {
        let mut model = Model::new();
        model.pending_until = [0, 300, u64::MAX][scenario];
        let mut reset = model.reset();
        let result = complete(reset.run());
        if scenario == 2 && !matches!(result, Some(Err(Error::Pending)))
            || scenario != 2 && !matches!(result, Some(Ok(_)))
        {
            return TestResult::Fail("source pending scenarios returned incorrect reset outcome");
        }
        let actual: Vec<_> = reset
            .io
            .log
            .iter()
            .filter(|a| !a.write && a.offset == 0x4a)
            .map(|a| a.at)
            .collect();
        if actual.as_slice() != *expected
            || reset.io.trigger.is_some_and(|at| {
                reset
                    .io
                    .log
                    .iter()
                    .any(|a| a.at > at && a.at - at < SOURCE_QUIET_MS)
            })
        {
            return TestResult::Fail(
                "pending read times or minimum FLR quiet time differs from extracted Linux C",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_flr_pending_and_quiet_timing_matches_extracted_linux_c
);
