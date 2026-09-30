use super::*;
use alloc::vec;
use core::{
    pin::Pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug)]
struct Fake {
    regs: Vec<u32>,
    vram: Vec<u8>,
    writes: Vec<(u32, u32)>,
    uploaded: usize,
    bad_reset: bool,
    locked_window: bool,
    boot_ready: bool,
    stop_ack: bool,
    violation: bool,
}
impl Io for Fake {
    fn read(&mut self, reg: u32) -> u32 {
        self.regs[reg as usize]
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.writes.push((reg, value));
        if self.locked_window && reg == 0x1b5 {
            return;
        }
        if self.bad_reset && matches!(reg, CNTL | CNTL2 | HUB_RESET) {
            return;
        }
        self.regs[reg as usize] = value;
        if reg == GPINT && value == STOP && self.stop_ack {
            self.regs[GPINT as usize] = 2 << 16;
            self.regs[STOP_REPLY as usize] = 0xdeaddead;
            self.regs[CNTL as usize] |= 1 << 20;
        }
        if reg == CNTL2 && value & 1 == 0 && self.boot_ready {
            if self.uploaded != self.vram.len() {
                self.violation = true;
            }
            self.regs[STATUS as usize] = 3;
        }
    }
    fn upload(&mut self, offset: usize, bytes: &[u8]) -> bool {
        if !reset_confirmed(self) || offset != self.uploaded {
            self.violation = true;
            return false;
        }
        self.vram[offset..offset + bytes.len()].copy_from_slice(bytes);
        self.uploaded += bytes.len();
        true
    }
}
fn fixture() -> (Pool, Engine<Fake>) {
    let bytes = super::super::amdgpu_dmub_firmware::tests::combined(256, 4);
    let prepared = super::super::amdgpu_dmub_firmware::Image::parse(&bytes)
        .unwrap()
        .prepare_dcn314(&[0x3c; 512])
        .unwrap();
    let layout = prepared.layout();
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: layout.size() as u64 + 4096,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: pure accounting model; Fake owns the only memory accesses.
    let pool = unsafe { Pool::from_owned_range(map, 0x2_0000_0000) }.unwrap();
    let allocation = pool.reserve(layout.size() as u64).unwrap();
    let placement = layout
        .place(
            allocation.address(),
            pool.address()..pool.address() + map.len,
        )
        .unwrap();
    let mut staging = vec![0; layout.size() as usize];
    prepared.stage(&mut staging).unwrap();
    let mut io = Fake {
        regs: vec![0; 0x478],
        vram: vec![0xa5; staging.len()],
        writes: Vec::new(),
        uploaded: 0,
        bad_reset: false,
        locked_window: false,
        boot_ready: true,
        stop_ack: true,
        violation: false,
    };
    io.regs[CNTL as usize] = ENABLE;
    (
        pool,
        Engine {
            io,
            authority: Cap::bootstrap(),
            allocation,
            layout,
            placement,
            fb_base: 0x2_0000_0000,
            fb_offset: 0x8000_0000,
            staging,
            state: State::Prepared,
            secure: false,
        },
    )
}

fn dmub_psp_boot_preserves_secure_windows() -> TestResult {
    let (_, mut engine) = fixture();
    engine.secure = true;
    engine.io.regs[0x1ad] = WINDOW_ENABLE | 0x123fff;
    engine.io.regs[0x1ae] = WINDOW_ENABLE | 0x100ffff;
    engine.io.regs[SEC_CNTL as usize] = 0x3400;
    if narf_scheduler::block_on_spin(engine.boot(Default::default())).is_err() {
        return TestResult::Fail("PSP-configured windows rejected");
    }
    if engine.io.writes.iter().any(|(reg, _)| {
        matches!(
            *reg,
            SEC_CNTL | 0x1a5 | 0x1a6 | 0x1ad | 0x1ae | 0x1b5..=0x1b8
        )
    }) {
        return TestResult::Fail("host overwrote PSP-owned secure windows");
    }
    if narf_scheduler::block_on_spin(engine.stop()).is_err() {
        return TestResult::Fail("secure firmware stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_psp_boot_preserves_secure_windows
);

fn dmub_direct_boot_orders_reset_upload_and_windows() -> TestResult {
    let (pool, mut engine) = fixture();
    let full = pool.available() + engine.allocation.size();
    if narf_scheduler::block_on_spin(engine.boot(BootOptions::default())).is_err()
        || engine.state != State::Running
        || engine.io.violation
        || engine.io.vram != engine.staging
    {
        return TestResult::Fail("reset/upload/start sequence");
    }
    let regs = &engine.io.regs;
    let address =
        |index: usize| regs[0x1b5 + index * 2] as u64 | (regs[0x1b6 + index * 2] as u64) << 32;
    if address(0) != 0x8000_0000
        || address(1) != 0x8000_0000 + engine.layout.region(Window::Stack).offset as u64
        || address(4) != engine.placement.inbox()
        || regs[0x1ad] != WINDOW_ENABLE | (engine.layout.region(Window::Instructions).size - 1)
        || regs[0x1b1] != WINDOW_ENABLE | 0x0400_0000 | engine.layout.region(Window::Mailbox).size
        || regs[0x1af] != 0
        || regs[0x1b4] != 0
        || regs[0x1d4] != 0x6400_0000
        || regs[0x1dc] != 0x6400_2000
        || regs[0x1d5] != 8192
        || regs[0x1dd] != 8192
        || regs[0x1f1] != (1 << 5) | (1 << 6) | (1 << 7) | (1 << 9) | (1 << 27)
    {
        return TestResult::Fail("Linux DCN314 window address/limit ABI");
    }
    if engine.io.writes.first() != Some(&(GPINT, STOP)) {
        return TestResult::Fail("live firmware not asked to stop");
    }
    if narf_scheduler::block_on_spin(engine.stop()).is_err() || engine.state != State::Stopped {
        return TestResult::Fail("shutdown did not verify reset");
    }
    drop(engine);
    if pool.available() != full {
        return TestResult::Fail("stopped allocation not returned");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_direct_boot_orders_reset_upload_and_windows
);

fn dmub_cancelled_boot_quarantines_failed_reset() -> TestResult {
    for bad_reset in [false, true] {
        let (pool, mut engine) = fixture();
        let reserved = engine.allocation.size();
        let free = pool.available();
        engine.io.stop_ack = false;
        engine.io.bad_reset = bad_reset;
        let mut future = alloc::boxed::Box::pin(engine.boot(BootOptions::default()));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("cancellation setup did not wait for STOP_FW");
        }
        drop(future);
        if engine.state != State::Starting || engine.stop_on_drop() == bad_reset {
            return TestResult::Fail("cancelled boot reused an unverified allocation");
        }
        if engine.io.uploaded != 0 {
            return TestResult::Fail("upload preceded verified stop");
        }
        drop(engine);
        if pool.available() != free + if bad_reset { 0 } else { reserved } {
            return TestResult::Fail("failed-stop retention or successful-stop release");
        }
        if bad_reset && pool.reserve(reserved).is_ok() {
            return TestResult::Fail("quarantined VRAM became allocatable");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_cancelled_boot_quarantines_failed_reset
);

fn dmub_revocation_stops_upload_but_allows_teardown() -> TestResult {
    let (pool, mut engine) = fixture();
    let revoked = engine.authority;
    let full = pool.available() + engine.allocation.size();
    let mut future = alloc::boxed::Box::pin(engine.boot(BootOptions::default()));
    if !matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return TestResult::Fail("upload did not yield");
    }
    revoked.revoke();
    if narf_scheduler::block_on_spin(future) != Err(Error::Revoked) || engine.io.uploaded != 4096 {
        return TestResult::Fail("revocation allowed later VRAM upload");
    }
    if narf_scheduler::block_on_spin(engine.stop()).is_err() {
        return TestResult::Fail("revocation blocked owned-device teardown");
    }
    drop(engine);
    if pool.available() != full {
        return TestResult::Fail("revoked stopped memory leaked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_revocation_stops_upload_but_allows_teardown
);

fn dmub_boot_timeout_does_not_publish_ready() -> TestResult {
    let (_, mut engine) = fixture();
    engine.io.boot_ready = false;
    if narf_scheduler::block_on_spin(engine.boot(BootOptions::default())) != Err(Error::BootTimeout)
        || engine.state != State::Failed
        || engine.allocation.reusable_for_test()
    {
        return TestResult::Fail("firmware readiness not required");
    }
    if !engine.stop_on_drop() {
        return TestResult::Fail("timeout cleanup failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_boot_timeout_does_not_publish_ready
);

fn dmub_locked_window_rejected_before_start() -> TestResult {
    let (_, mut engine) = fixture();
    engine.io.locked_window = true;
    if narf_scheduler::block_on_spin(engine.boot(BootOptions::default()))
        != Err(Error::ConfigurationFailed)
        || engine.state != State::Failed
        || !reset_confirmed(&mut engine.io)
    {
        return TestResult::Fail("unprogrammed firmware window released reset");
    }
    if !engine.stop_on_drop() {
        return TestResult::Fail("locked window cleanup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_locked_window_rejected_before_start
);

fn dmub_reset_timeout_never_overwrites_vram() -> TestResult {
    let (pool, mut engine) = fixture();
    let free = pool.available();
    engine.io.bad_reset = true;
    if narf_scheduler::block_on_spin(engine.boot(BootOptions::default())) != Err(Error::StopTimeout)
        || engine.io.uploaded != 0
        || engine.stop_on_drop()
    {
        return TestResult::Fail("failed reset was treated as safe to upload");
    }
    drop(engine);
    if pool.available() != free {
        return TestResult::Fail("failed reset returned VRAM to allocator");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_reset_timeout_never_overwrites_vram
);

fn dmub_mailbox_authority_checked_at_every_poll() -> TestResult {
    struct Pending<'a>(&'a mut usize);
    impl Future for Pending<'_> {
        type Output = Result<(), amdgpu_dmub::Error>;
        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            *self.0 += 1;
            Poll::Pending
        }
    }
    let cap: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    let revoke = cap;
    let mut polls = 0;
    let mut future = alloc::boxed::Box::pin(authorized(&cap, Pending(&mut polls)));
    let mut cx = Context::from_waker(Waker::noop());
    if future.as_mut().poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("first authorized poll");
    }
    revoke.revoke();
    if future.as_mut().poll(&mut cx) != Poll::Ready(Err(Error::Revoked)) {
        return TestResult::Fail("revoked mailbox future was polled");
    }
    drop(future);
    if polls != 1 {
        return TestResult::Fail("MMIO continued after revocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_mailbox_authority_checked_at_every_poll
);
