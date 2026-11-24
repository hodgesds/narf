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
    /// This generation's DMCUB register map; the special cases below
    /// model it, never the DCN 3.1.4 constants.
    table: Regs,
}
impl Io for Fake {
    fn read(&mut self, reg: u32) -> u32 {
        self.regs[reg as usize]
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.writes.push((reg, value));
        if self.locked_window && reg == self.table.cw_offset {
            return;
        }
        if self.bad_reset
            && (reg == self.table.cntl
                || self.table.cntl2 == Some(reg)
                || reg == self.table.hub_reset)
        {
            return;
        }
        self.regs[reg as usize] = value;
        if reg == self.table.gpint && value == STOP && self.stop_ack {
            self.regs[self.table.gpint as usize] = 2 << 16;
            self.regs[self.table.stop_reply as usize] = 0xdeaddead;
            self.regs[self.table.cntl as usize] |= 1 << 20;
        }
        // The firmware reports ready when reset is released: DCN 3.x on
        // the CNTL2 clear, DCN 2.0/2.1 on the CNTL enable (no CNTL2).
        let released = match self.table.cntl2 {
            Some(cntl2) => reg == cntl2 && value & 1 == 0,
            None => reg == self.table.cntl && value & ENABLE != 0,
        };
        if released && self.boot_ready {
            if self.uploaded != self.vram.len() {
                self.violation = true;
            }
            self.regs[self.table.status as usize] = 3;
        }
    }
    fn upload(&mut self, offset: usize, bytes: &[u8]) -> bool {
        let table = self.table;
        if !reset_confirmed(table, self) || offset != self.uploaded {
            self.violation = true;
            return false;
        }
        self.vram[offset..offset + bytes.len()].copy_from_slice(bytes);
        self.uploaded += bytes.len();
        true
    }
}
fn fixture_with(
    prepared: super::super::amdgpu_dmub_firmware::Prepared<'_>,
    table: Regs,
    cached_inbox: bool,
) -> (Pool, Engine<Fake>) {
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
        // The register numbers reach 0x32a2 on DCN 2.1; size the model
        // past the highest register either table addresses.
        regs: vec![0; 0x32a3],
        vram: vec![0xa5; staging.len()],
        writes: Vec::new(),
        uploaded: 0,
        bad_reset: false,
        locked_window: false,
        boot_ready: true,
        stop_ack: true,
        violation: false,
        table,
    };
    io.regs[table.cntl as usize] = ENABLE;
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
            regs: table,
            cached_inbox,
        },
    )
}
fn fixture() -> (Pool, Engine<Fake>) {
    let bytes = super::super::amdgpu_dmub_firmware::tests::combined(256, 4);
    let prepared = super::super::amdgpu_dmub_firmware::Image::parse(&bytes)
        .unwrap()
        .prepare_dcn314(&[0x3c; 512])
        .unwrap();
    fixture_with(prepared, Regs::DCN314, true)
}
/// A Renoir/Cezanne engine: the `prepare_dcn21` image for the
/// requested mailbox mode, on the DCN 2.1 register map.
fn fixture_dcn21(cached: bool) -> (Pool, Engine<Fake>) {
    // The shipping green_sardine blob is 0x0101002B (uncached); a blob
    // above 1.10.0 takes the cached CW4 path.
    let version = if cached { 0x010b_0000 } else { 0x0101_002b };
    let mut bytes = super::super::amdgpu_dmub_firmware::tests::combined(256, 4);
    let meta = bytes.len() - 256 - 4 - 64;
    bytes[meta + 12..meta + 16].copy_from_slice(&version.to_le_bytes());
    let prepared = super::super::amdgpu_dmub_firmware::Image::parse(&bytes)
        .unwrap()
        .prepare_dcn21(&[0x3c; 512])
        .unwrap();
    assert_eq!(prepared.cached_inbox(), cached);
    fixture_with(prepared, Regs::DCN21, cached)
}

fn dmub_psp_boot_preserves_secure_windows() -> TestResult {
    let (_, mut engine) = fixture();
    engine.secure = true;
    engine.io.regs[0x1ad] = WINDOW_ENABLE | 0x123fff;
    engine.io.regs[0x1ae] = WINDOW_ENABLE | 0x100ffff;
    engine.io.regs[Regs::DCN314.sec_cntl as usize] = 0x3400;
    if narf_scheduler::block_on_spin(engine.boot(Default::default())).is_err() {
        return TestResult::Fail("PSP-configured windows rejected");
    }
    // The PSP-owned secure windows: SEC_CNTL, CW0/1 BASE, CW0/1 TOP,
    // CW0/1 OFFSET/HIGH — no host write may touch any of them.
    let regs = Regs::DCN314;
    if engine.io.writes.iter().any(|(reg, _)| {
        *reg == regs.sec_cntl
            || *reg == regs.cw_base
            || *reg == regs.cw_base + 1
            || *reg == regs.cw_top
            || *reg == regs.cw_top + 1
            || (regs.cw_offset..=regs.cw_offset + 3).contains(reg)
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
    if engine.io.writes.first() != Some(&(Regs::DCN314.gpint, STOP)) {
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
        || !reset_confirmed(engine.regs, &mut engine.io)
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

/// `dm_dmub_hw_resume`'s two branches on the engine. A DMCUB still running
/// its DAL firmware is `is_hw_init` and passes the auto-load wait. One that
/// S0i3 powered off (DMCUB_CNTL disabled, SCRATCH0 cleared) is not
/// initialized, and boots again from Stopped on the same allocation.
fn dmub_s0ix_resume_checks_hw_init_and_reboots_a_lost_dmcub() -> TestResult {
    let (_pool, mut engine) = fixture();
    if narf_scheduler::block_on_spin(engine.boot(BootOptions::default())).is_err() {
        return TestResult::Fail("boot");
    }
    if engine.is_hw_init() != Ok(true)
        || narf_scheduler::block_on_spin(engine.wait_for_auto_load()).is_err()
    {
        return TestResult::Fail("a running DMCUB not seen as initialized");
    }
    engine.io.regs[Regs::DCN314.cntl as usize] &= !ENABLE;
    engine.io.regs[Regs::DCN314.status as usize] = 0;
    if engine.is_hw_init() != Ok(false) {
        return TestResult::Fail("a powered-off DMCUB seen as initialized");
    }
    engine.state = State::Stopped;
    // The model tracks one staging pass; a new boot stages from offset 0.
    engine.io.uploaded = 0;
    if narf_scheduler::block_on_spin(engine.boot(BootOptions::default())).is_err()
        || engine.state != State::Running
        || engine.is_hw_init() != Ok(true)
    {
        return TestResult::Fail("the lost DMCUB did not boot again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_s0ix_resume_checks_hw_init_and_reboots_a_lost_dmcub
);

/// Renoir/Cezanne cached-mailbox boot: a firmware above 1.10.0 takes
/// the CW4 window (inbox 0x64000000), on the DCN 2.1 register map.
/// Window addresses, TOPs and mailbox bases mirror the DCN314 test.
fn dmub_dcn21_cached_boot_programs_cw4_mailbox() -> TestResult {
    let (pool, mut engine) = fixture_dcn21(true);
    let full = pool.available() + engine.allocation.size();
    if narf_scheduler::block_on_spin(engine.boot(BootOptions::default())).is_err()
        || engine.state != State::Running
        || engine.io.violation
        || engine.io.vram != engine.staging
    {
        return TestResult::Fail("dcn21 cached reset/upload/start sequence");
    }
    let regs = &engine.io.regs;
    let address =
        |index: usize| regs[0x325f + index * 2] as u64 | (regs[0x3260 + index * 2] as u64) << 32;
    if address(0) != 0x8000_0000
        || address(1) != 0x8000_0000 + engine.layout.region(Window::Stack).offset as u64
        || address(4) != engine.placement.inbox()
        || regs[0x3257] != WINDOW_ENABLE | (engine.layout.region(Window::Instructions).size - 1)
        || regs[0x325b] != WINDOW_ENABLE | 0x0400_0000 | engine.layout.region(Window::Mailbox).size
        || regs[0x3259] != 0
        || regs[0x327e] != 0x6400_0000
        || regs[0x3286] != 0x6400_2000
        || regs[0x327f] != 8192
        || regs[0x3287] != 8192
        || regs[0x329b] != (1 << 5) | (1 << 6) | (1 << 7) | (1 << 9) | (1 << 27)
    {
        return TestResult::Fail("Linux DCN21 window address/limit ABI");
    }
    if engine.io.writes.first() != Some(&(Regs::DCN21.gpint, STOP)) {
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
    dmub_dcn21_cached_boot_programs_cw4_mailbox
);

/// The shipping green_sardine blob (0x0101002B) takes the uncached
/// REGION4 mailbox: inbox/outbox at GPU 0x80000000/0x80002000, CW4
/// skipped, REGION4 TOP = mailbox size - 1 with ENABLE.
fn dmub_dcn21_uncached_boot_programs_region4_mailbox() -> TestResult {
    let (_pool, mut engine) = fixture_dcn21(false);
    if narf_scheduler::block_on_spin(engine.boot(BootOptions::default())).is_err()
        || engine.state != State::Running
        || engine.io.violation
        || engine.io.vram != engine.staging
    {
        return TestResult::Fail("dcn21 uncached reset/upload/start sequence");
    }
    let regs = &engine.io.regs;
    let mailbox = engine.layout.region(Window::Mailbox).size;
    if regs[0x327e] != 0x8000_0000
        || regs[0x3286] != 0x8000_2000
        || regs[0x327f] != 8192
        || regs[0x3287] != 8192
        || regs[0x324b] != WINDOW_ENABLE | (mailbox - 1)
        || regs[0x3240] != engine.placement.inbox() as u32
        || regs[0x3241] != (engine.placement.inbox() >> 32) as u32
        || regs[0x325b] != 0
        || regs[0x3257] != WINDOW_ENABLE | (engine.layout.region(Window::Instructions).size - 1)
    {
        return TestResult::Fail("Linux DCN21 uncached mailbox ABI");
    }
    if narf_scheduler::block_on_spin(engine.stop()).is_err() || engine.state != State::Stopped {
        return TestResult::Fail("shutdown did not verify reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu-dmub",
    dmub_dcn21_uncached_boot_programs_region4_mailbox
);
