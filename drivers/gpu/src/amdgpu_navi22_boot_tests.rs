use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

pub(crate) fn report() -> Report {
    Report {
        reset: None,
        smu: smu::Versions {
            firmware: 0x413f00,
            interface: 0xe,
        },
        gfx: psp::GfxBootStatus {
            cp_stat: 0,
            rlc_bootload: 1 << 31,
        },
        power: None,
        power_status: None,
        media_firmware: psp::MediaFirmware::default(),
        memory_aperture: None,
        sdma: None,
        dmub: None,
        queues: None,
        interrupts: None,
        media: None,
    }
}
struct Fake {
    fail: Option<Stage>,
    stall: Option<Stage>,
    calls: Vec<Stage>,
    progress: Vec<(Stage, Option<Result<(), Error>>)>,
    missing_report: bool,
    _owned: crate::amdgpu_vram::Reservation,
    dropped: Arc<AtomicBool>,
}
impl Drop for Fake {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
impl Backend for Fake {
    fn progress(&mut self, stage: Stage, result: Option<Result<(), Error>>) {
        self.progress.push((stage, result));
    }
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        self.calls.push(stage);
        if self.fail == Some(stage) {
            return Err(Error::Psp(psp::Error::Rejected(7)));
        }
        if self.stall == Some(stage) {
            core::future::pending::<()>().await;
        }
        Ok(())
    }
    fn report(&self) -> Result<Report, Error> {
        if self.missing_report {
            Err(Error::Invalid)
        } else {
            Ok(report())
        }
    }
}
fn pool(len: u64) -> Pool {
    // SAFETY: bookkeeping-only tests never dereference this VRAM mapping.
    unsafe {
        Pool::from_owned_range(
            narf_bus::MmioRegion {
                phys: narf_memory::PhysAddr::new(0),
                virt: 0,
                len,
                kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
            },
            0x8_0000_0000,
        )
    }
    .unwrap()
}
fn sequence() -> (Pool, Arc<AtomicBool>, Sequence<Fake>) {
    let pool = pool(8192);
    let mut owned = pool.reserve(4096).unwrap();
    owned.publish();
    let dropped = Arc::new(AtomicBool::new(false));
    let fake = Fake {
        fail: None,
        stall: None,
        calls: Vec::new(),
        progress: Vec::new(),
        missing_report: false,
        _owned: owned,
        dropped: dropped.clone(),
    };
    (
        pool,
        dropped,
        Sequence {
            backend: fake,
            state: State::Prepared,
        },
    )
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn navi22_boot_orders_stages_and_keeps_successful_owners() -> TestResult {
    let (pool, dropped, mut sequence) = sequence();
    if run(sequence.run()) != Ok(report())
        || sequence.state != State::FirmwareReady(report())
        || sequence.backend.calls != STAGES
        || sequence.backend.progress
            != STAGES
                .into_iter()
                .flat_map(|stage| [(stage, None), (stage, Some(Ok(())))])
                .collect::<Vec<_>>()
        || dropped.load(Ordering::SeqCst)
        || pool.available() != 4096
    {
        return TestResult::Fail("wrong bring-up order/report or premature owner destruction");
    }
    if run(sequence.run()) != Err(Error::Busy) || sequence.backend.calls.len() != STAGES.len() {
        return TestResult::Fail("successful cold boot replayed");
    }
    drop(sequence);
    if !dropped.load(Ordering::SeqCst) || pool.available() != 4096 {
        return TestResult::Fail("drop failed to quarantine published memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_orders_stages_and_keeps_successful_owners
);

fn navi22_boot_failure_stops_at_each_stage_without_cleanup_or_replay() -> TestResult {
    for (index, stage) in STAGES.into_iter().enumerate() {
        let (pool, dropped, mut sequence) = sequence();
        sequence.backend.fail = Some(stage);
        let error = Error::Psp(psp::Error::Rejected(7));
        if run(sequence.run()) != Err(error)
            || sequence.state != (State::Failed { stage, error })
            || sequence.backend.calls != STAGES[..=index]
            || sequence.backend.progress.last() != Some(&(stage, Some(Err(error))))
            || sequence.backend.progress.len() != (index + 1) * 2
            || dropped.load(Ordering::SeqCst)
            || run(sequence.run()) != Err(Error::Busy)
            || pool.available() != 4096
        {
            return TestResult::Fail(
                "stage failure continued/replayed or discarded its hardware owner",
            );
        }
        drop(sequence);
        if pool.available() != 4096 {
            return TestResult::Fail("failed bring-up recycled device-owned memory");
        }
    }
    let (_, _, mut sequence) = sequence();
    sequence.backend.missing_report = true;
    if run(sequence.run()) != Err(Error::Invalid)
        || matches!(sequence.state, State::FirmwareReady(_))
    {
        return TestResult::Fail("missing firmware observations published readiness");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_failure_stops_at_each_stage_without_cleanup_or_replay
);

fn navi22_boot_cancel_at_each_stage_retains_session_and_ownership() -> TestResult {
    for (index, stage) in STAGES.into_iter().enumerate() {
        let (pool, dropped, mut sequence) = sequence();
        sequence.backend.stall = Some(stage);
        {
            let mut future = core::pin::pin!(sequence.run());
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("blocked stage completed");
            }
        }
        if sequence.state != State::Running(stage)
            || sequence.backend.calls != STAGES[..=index]
            || sequence.backend.progress.last() != Some(&(stage, None))
            || sequence.backend.progress.len() != index * 2 + 1
            || dropped.load(Ordering::SeqCst)
            || pool.available() != 4096
            || run(sequence.run()) != Err(Error::Busy)
            || sequence.backend.calls.len() != index + 1
        {
            return TestResult::Fail("cancel lost progress/owner or resumed the sequence");
        }
        drop(sequence);
        if !dropped.load(Ordering::SeqCst) || pool.available() != 4096 {
            return TestResult::Fail("cancelled owner was not quarantined on drop");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_cancel_at_each_stage_retains_session_and_ownership
);

pub(crate) fn gpu() -> AmdGpu {
    use crate::amdgpu_discovery as d;
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 0x80000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let ip = |id, v: (u8, u8, u8)| d::IpBlock {
        hw_id: id,
        instance: 0,
        major: v.0,
        minor: v.1,
        revision: v.2,
        sub_revision: 0,
        variant: 0,
        base_addrs: [0; d::MAX_BASE_ADDRS],
        num_bases: 3,
    };
    AmdGpu {
        regs: map,
        fb_bar: narf_bus::MmioRegion {
            len: 16 << 20,
            ..map
        },
        chip: crate::amdgpu::__test_chip_info_for_pci_id(
            crate::amdgpu::AMD_VENDOR,
            crate::amdgpu::NAVI22,
        )
        .unwrap(),
        vram: crate::amdgpu::VramInfo {
            base: 0,
            size: 12 << 30,
            visible_size: 16 << 20,
        },
        mode: None,
        fw_loaded: false,
        gc_info: None,
        vbios: None,
        ip_blocks: vec![
            ip(d::HW_ID_GC, (10, 3, 2)),
            ip(d::HW_ID_MP0, (11, 0, 11)),
            ip(d::HW_ID_MP1, (11, 0, 11)),
            ip(d::HW_ID_SDMA0, (5, 2, 2)),
            ip(d::HW_ID_NBIF, (3, 3, 0)),
            ip(d::HW_ID_HDP, (5, 0, 2)),
            ip(d::HW_ID_OSSSYS, (5, 0, 3)),
        ],
    }
}
fn firmware() -> Firmware {
    Firmware {
        sos: sos::tests::firmware(),
        smc: smu::tests::firmware(),
        graphics: gfx::tests::fixture(),
        power: None,
        dmub: None,
        display: None,
    }
}
fn navi22_runtime_commands_require_completed_boot_and_retained_tmr() -> TestResult {
    let pool = pool(16 << 20);
    let authority = Cap::bootstrap();
    // SAFETY: constructor performs no I/O, and every runtime entry must fail
    // before touching these intentionally unmapped GPU addresses.
    let mut boot = unsafe { ColdBoot::new(&gpu(), authority, &pool, firmware()) }.unwrap();
    for state in [
        State::Prepared,
        State::Running(Stage::DmubStart),
        State::Failed {
            stage: Stage::DmubStart,
            error: Error::Invalid,
        },
        State::FirmwareReady(report()), // no live PSP/TMR in this fixture
        State::Released,
    ] {
        boot.sequence.state = state;
        if run(boot.dmub_hpd(0)) != Err(Error::Busy)
            || run(boot.dmub_aux(0, 0x90, 0x202, &mut [0; 6])) != Err(Error::Busy)
            || boot.dmub_notification() != Err(Error::Busy)
            || boot.dmub_mailbox_state().is_some()
        {
            return TestResult::Fail("runtime command escaped boot/TMR ownership gate");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_runtime_commands_require_completed_boot_and_retained_tmr
);
fn navi22_native_display_requires_routes_and_firmware_readiness() -> TestResult {
    let pool = pool(16 << 20);
    // SAFETY: constructor performs no I/O on this unmapped fixture.
    let mut boot = unsafe { ColdBoot::new(&gpu(), Cap::bootstrap(), &pool, firmware()) }.unwrap();
    // No prepared VBIOS routes: nothing to bind, and nothing claimed.
    if boot.prepare_display() != Err(Error::Invalid) || boot.display_connectors().is_some() {
        return TestResult::Fail("display claimed without routes");
    }
    for state in [
        State::Prepared,
        State::Running(Stage::DmubStart),
        State::Failed {
            stage: Stage::DmubStart,
            error: Error::Invalid,
        },
        State::Released,
    ] {
        boot.sequence.state = state;
        if run(boot.detect_displays()).err() != Some(Error::Busy) {
            return TestResult::Fail("detection before firmware readiness");
        }
    }
    boot.sequence.state = State::FirmwareReady(report());
    if run(boot.detect_displays()).err() != Some(Error::Invalid) {
        return TestResult::Fail("detection without an owner");
    }
    // Opting into DMUB AUX does not bypass the boot/TMR gate.
    boot.allow_dmub_aux();
    if run(boot.dmub_hpd(0)) != Err(Error::Busy) {
        return TestResult::Fail("DMUB HPD escaped its gate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_native_display_requires_routes_and_firmware_readiness
);
fn navi22_boot_outlives_the_controller_lock() -> TestResult {
    fn send_static<T: Send + 'static>(_: &T) {}
    fn send_future<T: Send>(_: &T) {}
    let pool = pool(16 << 20);
    let cap = Cap::bootstrap();
    cap.revoke();
    let mut boot = {
        let gpu = narf_lib::sync::IrqSafeSpinLock::new(gpu());
        let guard = gpu.lock();
        // SAFETY: bookkeeping-only constructor; revoked authority will reject
        // all I/O. This descriptor has no backing GPU and no live owner.
        unsafe { ColdBoot::new(&guard, cap, &pool, firmware()) }.unwrap()
    };
    send_static(&boot);
    let result = {
        let future = boot.run();
        send_future(&future);
        run(future)
    };
    if result != Err(Error::Sos(sos::Error::Revoked)) {
        return TestResult::Fail(
            "owned boot session could not run after releasing controller lock",
        );
    }
    drop(boot);
    if pool.available() != 16 << 20 {
        return TestResult::Fail("unpublished snapshot session leaked staging");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_outlives_the_controller_lock
);
fn navi22_boot_training_failure_prevents_sos_publication() -> TestResult {
    let mut gpu = gpu();
    gpu.fb_bar.len = 64 << 20;
    gpu.vram.visible_size = 64 << 20;
    let mut regs = vec![0; gpu.regs.len as usize / 4];
    regs[0x91] = u32::MAX;
    gpu.regs.virt = regs.as_mut_ptr() as u64;
    let original = regs.clone();
    let pool = pool(16 << 20);
    let authority = Cap::bootstrap();
    let exchange = crate::amdgpu_vram_boot::Training {
        p2c: (12 << 30) - 0x8000,
        c2p: (12 << 30) - (9 << 20),
        size: 4096,
    };
    // SAFETY: private RAM register fixture, absent SOS aborts before accessing
    // the intentionally unmapped BAR0 or publishing any PSP reservation.
    let mut boot =
        unsafe { ColdBoot::new_with_training(&gpu, authority, &pool, firmware(), exchange) }
            .unwrap();
    if regs != original
        || pool.available() != 16 << 20
        || boot.training_state() != Some(gddr6::State::Prepared)
    {
        return TestResult::Fail("training constructor changed MMIO or claimed the SOS mailbox");
    }
    let error = Error::Training(gddr6::Error::DeviceGone);
    if run(boot.run()) != Err(error)
        || boot.state()
            != (State::Failed {
                stage: Stage::MemoryTraining,
                error,
            })
        || regs != original
        || boot.sequence.backend.bootstrap.is_some()
        || boot.training_data().is_some()
        || run(boot.run()) != Err(Error::Busy)
    {
        return TestResult::Fail(
            "training failure reached firmware bootstrap or lost failure state",
        );
    }
    drop(boot);
    authority.revoke();
    gpu.regs.virt = 0;
    // SAFETY: constructor must reject revoked PCI authority before any I/O.
    if unsafe { ColdBoot::new_with_training(&gpu, authority, &pool, firmware(), exchange) }.err()
        != Some(Error::Training(gddr6::Error::Revoked))
    {
        return TestResult::Fail("training preparation bypassed PCI authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_training_failure_prevents_sos_publication
);
fn navi22_boot_preflight_and_real_backend_revocation() -> TestResult {
    let registry = Cap::bootstrap();
    registry.revoke();
    let gpu = gpu();
    if !matches!(
        Firmware::open(&gpu, &registry),
        Err(Error::Sos(sos::Error::Revoked))
    ) {
        return TestResult::Fail("coordinated firmware preparation bypassed registry authority");
    }
    let mut bad = self::gpu();
    bad.ip_blocks[0].num_bases = 1;
    if !matches!(
        Firmware::open(&bad, &registry),
        Err(Error::Psp(psp::Error::Unsupported))
    ) {
        return TestResult::Fail("missing RLC register bank reached firmware registry");
    }
    let pool = pool(16 << 20);
    let authority = Cap::bootstrap();
    authority.revoke();
    // SAFETY: constructor is bookkeeping-only; revoked authority must prevent
    // every MMIO in run. Firmware is synthetic and no hardware consumes it.
    let mut boot = unsafe { ColdBoot::new(&gpu, authority, &pool, firmware()) }.unwrap();
    if boot.state() != State::Prepared
        || pool.available() != 15 << 20
        || boot.gfx_boot_status().is_some()
        || !matches!(boot.take_psp(), Err(Error::Busy))
    {
        return TestResult::Fail("constructor touched hardware or released incomplete PSP owner");
    }
    let error = Error::Sos(sos::Error::Revoked);
    if run(boot.run()) != Err(error)
        || boot.state()
            != (State::Failed {
                stage: Stage::Sos,
                error,
            })
        || run(boot.run()) != Err(Error::Busy)
        || !matches!(boot.take_psp(), Err(Error::Busy))
        || boot.sequence.backend.psp.is_some()
        || gpu.fw_loaded
    {
        return TestResult::Fail("revoked SOS continued to PSP or published acceleration");
    }
    drop(boot);
    if pool.available() != 16 << 20 {
        return TestResult::Fail("unpublished bootstrap allocation leaked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_preflight_and_real_backend_revocation
);
fn navi22_boot_queue_preparation_requires_hubs_and_sdma() -> TestResult {
    let pool = pool(16 << 20);
    let authority = Cap::bootstrap();
    let doorbells = crate::amdgpu_cp_navi22::tests::doorbells();
    // SAFETY: bookkeeping-only constructor; no I/O happens in this test.
    let mut boot = unsafe { ColdBoot::new(&gpu(), authority, &pool, firmware()) }.unwrap();
    let available = pool.available();
    if boot.prepare_queues(doorbells) != Err(Error::Invalid)
        || boot.sequence.backend.queues.is_some()
        || pool.available() != available
    {
        return TestResult::Fail("queues prepared without VMID0 hubs and SDMA proof");
    }
    boot.sequence.state = State::Running(Stage::Kiq);
    if boot.prepare_queues(doorbells) != Err(Error::Busy) {
        return TestResult::Fail("queues prepared during a run");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_queue_preparation_requires_hubs_and_sdma
);

fn navi22_boot_fence_interrupts_map_to_their_engine() -> TestResult {
    use crate::{amdgpu_fence_navi22::Engine, amdgpu_ih_navi22::Iv};
    let iv = |client, src, ring_id| Iv {
        client,
        src,
        ring_id,
        vmid: 0,
        vmid_src: false,
        timestamp: 0,
        timestamp_src: false,
        pasid: 0,
        node_id: 0,
        src_data: [0; 4],
    };
    // ring_id = queue << 4 | me << 2 | pipe (gfx_v10_0_eop_irq).
    for (entry, expected) in [
        (iv(0x14, 181, 0x00), Some(Engine::Gfx)),
        (iv(0x14, 181, 0x04), Some(Engine::Compute)),
        (iv(0x14, 181, 0x09), Some(Engine::Kiq)),
        (iv(0x14, 181, 0x0c), None),
        (iv(0x08, 224, 0), Some(Engine::Sdma0)),
        (iv(0x09, 224, 0), Some(Engine::Sdma1)),
        (iv(0x14, 184, 0), None),
        (iv(0x08, 0, 0), None),
    ] {
        if fence_engine(&entry) != expected {
            return TestResult::Fail("IH entry routed to the wrong fence engine");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_fence_interrupts_map_to_their_engine
);

fn navi22_recovery_and_tdr_require_a_completed_recoverable_boot() -> TestResult {
    let pool = pool(16 << 20);
    let authority = Cap::bootstrap();
    // SAFETY: constructor performs no I/O; every entry below must refuse
    // before touching these intentionally unmapped GPU addresses.
    let mut boot = unsafe { ColdBoot::new(&gpu(), authority, &pool, firmware()) }.unwrap();
    for state in [
        State::Prepared,
        State::Running(Stage::IbTests),
        State::Failed {
            stage: Stage::IbTests,
            error: Error::Invalid,
        },
        State::Released,
    ] {
        boot.sequence.state = state;
        if boot.queue_progress().err() != Some(Error::Busy)
            || boot.recoverable()
            || boot.queues_verified()
        {
            return TestResult::Fail("TDR/recovery escaped the completed-boot gate");
        }
    }
    // Completed, but without board power, PSP and IH (this fixture): no
    // queues to sample and recovery refused before any I/O.
    boot.sequence.state = State::FirmwareReady(report());
    if boot.queue_progress().map(|v| v.len()) != Ok(0) || boot.recoverable() {
        return TestResult::Fail("unprepared owner sampled or recoverable");
    }
    // SAFETY: refused before the IH owner (absent here) is touched.
    if run(unsafe { boot.quiesce_for_reset() }) != Err(Error::Busy) {
        return TestResult::Fail("quiesce of an unrecoverable owner");
    }
    let addr = narf_bus::PcieAddr::new(0, 3, 0, 0);
    let device = narf_bus::BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        kind: narf_bus::BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
        id: narf_bus::DeviceId {
            vendor: 0x1002,
            device: 0x73df,
            class: 0x030000,
            subsystem_vendor: 0x1462,
            subsystem_id: 0x3985,
        },
    };
    // SAFETY: refused before any constructor or I/O runs.
    if unsafe { boot.into_recovery(device) }.err() != Some(Error::Busy) {
        return TestResult::Fail("rebuilt an unrecoverable owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_recovery_and_tdr_require_a_completed_recoverable_boot
);

/// Linux ordering the firmware path must keep: PSP TMR reservation and SMC
/// precede everything else (SETUP_TMR itself is inside `Smc`, after PMFW),
/// GC golden settings precede SDMA, and DMUB starts only after every queue
/// and fence proof, so a DMUB failure cannot cost GFX/SDMA/media.
fn navi22_stage_order_matches_linux_firmware_path() -> TestResult {
    let at = |stage| STAGES.iter().position(|s| *s == stage).unwrap();
    if at(Stage::TrustedMemory) + 1 != at(Stage::Smc)
        || at(Stage::Smc) >= at(Stage::Graphics)
        || at(Stage::GoldenSettings) >= at(Stage::SdmaTest)
        || at(Stage::Interrupts) >= at(Stage::GoldenSettings)
        || at(Stage::DmubStart) <= at(Stage::IbTests)
        || at(Stage::DmubStart) <= at(Stage::FenceInterrupts)
        || at(Stage::DmubStart) >= at(Stage::Media)
        || at(Stage::DmubQuiesce) >= at(Stage::Graphics)
    {
        return TestResult::Fail("firmware stage order diverges from Linux");
    }
    use crate::amdgpu_dmub_navi22::Error as Dmub;
    for error in [Dmub::BootTimeout, Dmub::Invalid, Dmub::Readback, Dmub::Busy] {
        if dmub_result(Err(error)).is_err() {
            return TestResult::Fail("ordinary DMUB failure was fatal to the boot");
        }
    }
    for error in [Dmub::DeviceGone, Dmub::Revoked] {
        if dmub_result(Err(error)) != Err(Error::Dmub(error)) {
            return TestResult::Fail("device loss during DMUB start ignored");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_stage_order_matches_linux_firmware_path
);

/// HPD arming programs the HPD/AUX/DDC engines; a default firmware-only boot
/// (neither `amdgpu.native_display` nor `amdgpu.display_probe`) must not.
fn navi22_hotplug_is_opt_in_with_the_display() -> TestResult {
    use crate::amdgpu_navi22_platform as platform;
    let before = platform::display_engines_requested();
    if before {
        return TestResult::Fail("display engines armed without an opt-in flag");
    }
    platform::set_display_engines(true);
    let armed = platform::display_engines_requested();
    platform::set_display_engines(before);
    if !armed || platform::display_engines_requested() {
        return TestResult::Fail("display opt-in not honoured");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_hotplug_is_opt_in_with_the_display
);

/// A fused-off DMCUB drops the DMUB owner and continues; a readback failure
/// or device loss still stops the boot at DmubQuiesce.
fn navi22_dmub_quiesce_tolerates_fused_off_dmcub() -> TestResult {
    use crate::amdgpu_dmub_navi22::Error as Dmub;
    if dmub_quiesce_result(Ok(())) != Ok(true)
        || dmub_quiesce_result(Err(Dmub::Unsupported)) != Ok(false)
    {
        return TestResult::Fail("fused-off DMCUB stopped the boot");
    }
    for error in [Dmub::Readback, Dmub::DeviceGone, Dmub::Revoked] {
        if dmub_quiesce_result(Err(error)) != Err(Error::Dmub(error)) {
            return TestResult::Fail("DMUB reset fault tolerated");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_dmub_quiesce_tolerates_fused_off_dmcub
);
