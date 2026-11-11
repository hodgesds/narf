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
        backlight_percent: None,
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
fn navi22_boot_retains_board_bios_for_reset_and_recovery() -> TestResult {
    let mut original = gpu();
    original.vbios = Some(crate::amdgpu_vbios::tests::fixture());
    let bios = original.vbios.as_ref().unwrap();
    let expected = bios.bytes().to_vec();
    let source = bios.source();
    let original_ptr = bios.bytes().as_ptr();
    let pool = pool(16 << 20);
    // SAFETY: construction only copies metadata and reserves owned storage;
    // it performs no I/O through these intentionally unmapped addresses.
    let first = unsafe { ColdBoot::new(&original, Cap::bootstrap(), &pool, firmware()) }.unwrap();
    let Some(bios) = first.sequence.backend.gpu.vbios.as_ref() else {
        return TestResult::Fail("cold boot discarded the board BIOS before reset/post");
    };
    if bios.bytes() != expected || bios.source() != source || bios.bytes().as_ptr() == original_ptr
    {
        return TestResult::Fail("cold-boot BIOS changed source/bytes or aliases the controller");
    }
    // Recovery rebuilds through new_rdna2 using the first owner's snapshot.
    // Exercise that handoff too, without issuing a reset or publishing queues.
    let retained_ptr = bios.bytes().as_ptr();
    // SAFETY: same no-I/O construction contract; neither owner has been run.
    let second = unsafe {
        ColdBoot::new_rdna2(
            &first.sequence.backend.gpu,
            Cap::bootstrap(),
            &pool,
            firmware(),
        )
    }
    .unwrap();
    drop(first);
    drop(original);
    let Some(bios) = second.sequence.backend.gpu.vbios.as_ref() else {
        return TestResult::Fail("recovery snapshot discarded the retained board BIOS");
    };
    if bios.bytes() != expected || bios.source() != source || bios.bytes().as_ptr() == retained_ptr
    {
        return TestResult::Fail("recovery BIOS does not own the original validated board image");
    }
    if snapshot(&gpu()).unwrap().vbios.is_some() {
        return TestResult::Fail("snapshot fabricated a BIOS for a BIOS-less GPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_retains_board_bios_for_reset_and_recovery
);

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
    gpu.vbios = Some(crate::amdgpu_vbios::tests::fixture());
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
        || boot
            .sequence
            .backend
            .gpu
            .vbios
            .as_ref()
            .map(|bios| (bios.bytes(), bios.source()))
            != gpu.vbios.as_ref().map(|bios| (bios.bytes(), bios.source()))
    {
        return TestResult::Fail(
            "training constructor changed MMIO, claimed SOS or discarded the board BIOS",
        );
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
        (iv(0x01, 224, 0), Some(Engine::Sdma2)),
        (iv(0x05, 224, 0), Some(Engine::Sdma3)),
        (iv(0x14, 184, 0), None),
        (iv(0x08, 0, 0), None),
    ] {
        if fence_engine(&entry) != expected {
            return TestResult::Fail("IH entry routed to the wrong fence engine");
        }
    }
    TestResult::Pass
}
fn navi22_cp_faults_target_only_owned_queues() -> TestResult {
    use crate::{amdgpu_fence_navi22::Engine, amdgpu_ih_navi22::Iv};
    for src in [183, 184, 185] {
        let mut iv = Iv {
            client: 0x14,
            src,
            vmid: 3,
            pasid: 17,
            ..Iv::default()
        };
        assert_eq!(cp_fault_engine(&iv), Some(Engine::Gfx));
        iv.ring_id = 0x04;
        assert_eq!(
            cp_fault_engine(&iv),
            (src != 185).then_some(Engine::Compute)
        );
        for ring_id in [0x01, 0x05, 0x09, 0x10, 0x14, 0x24, 0x7f] {
            iv.ring_id = ring_id;
            assert_eq!(cp_fault_engine(&iv), None, "unowned ring {ring_id:#x}");
        }
        iv.ring_id = 0;
        iv.client = 8;
        assert_eq!(cp_fault_engine(&iv), None);
    }
    for src in [0, 181, 182, 186, 224] {
        let iv = Iv {
            client: 0x14,
            src,
            ..Iv::default()
        };
        assert_eq!(cp_fault_engine(&iv), None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-cp-faults",
    navi22_cp_faults_target_only_owned_queues
);
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_boot_fence_interrupts_map_to_their_engine
);

fn navi22_recovery_and_tdr_require_a_completed_recoverable_boot() -> TestResult {
    // The session and its recovery result cross several owning call frames.
    // Keep each within a small fraction of the 64 KiB aarch64 boot stack;
    // the old inline hardware made this call chain exceed that stack.
    if core::mem::size_of::<ColdBoot>() > 1024
        || core::mem::size_of::<Result<ColdBoot, Error>>() > 1024
    {
        return TestResult::Fail("boot owner exceeds the recovery stack budget");
    }
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

/// A trained Navi22 owner is recoverable and survives the recovery rebuild
/// (#1796): `into_recovery` retains its finished trainer, marks the
/// rebuilt owner for replay, and the rebuilt owner's MemoryTraining stage
/// replays the cache (`PSP_MEM_TRAIN_RESUME`) after the mode1 reset and
/// before SOS loads. A trainer that never finished keeps the owner
/// unrecoverable, and a failed or cancelled replay wedges the trainer so
/// no later rebuild can trust it.
fn navi22_trained_owner_survives_recovery_rebuild() -> TestResult {
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
    // Back the fixture GPU's registers with zeroes, as the PSP tests do:
    // `Psp::new_rdna2` reads the FB_LOCATION registers while validating
    // the pool, and the unmapped fixture addresses would fault. The pool
    // is the consistent aperture for those zeroed registers (GPU address
    // 0, BAR physical 0x9000_0000), and the BAR is wide enough for the
    // 32 MiB training preimage the shared fixture GPU cannot fit.
    let mut regs = vec![0u32; 0x80000 / 4];
    let mut trained_gpu = gpu();
    // Real Navi22 discovery reports MMHUB 2.1.0; `into_recovery` rebuilds
    // the memory hubs (`Gmc::new_rdna2` validates both hubs), so the
    // fixture GPU needs the block — same pattern as `rdna2_gpu` in
    // amdgpu_gmc_navi22_tests.rs. Local only: the GMC tests' helpers push
    // their own MMHUB block, so adding one to the shared `gpu()` would
    // create duplicate instance-0 MMHUB blocks and break them.
    let mut mm = trained_gpu.ip_blocks[0]; // GC block as the template
    mm.hw_id = crate::amdgpu_discovery::HW_ID_MMHUB;
    (mm.major, mm.minor, mm.revision) = (2, 1, 0);
    mm.base_addrs[0] = 0x20000 / 4;
    trained_gpu.ip_blocks.push(mm);
    trained_gpu.regs = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xa000_0000),
        virt: regs.as_mut_ptr() as u64,
        len: regs.len() as u64 * 4,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    trained_gpu.fb_bar = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0x9000_0000),
        virt: 0,
        len: 256 << 20,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    trained_gpu.vram.base = 0x9000_0000;
    trained_gpu.vram.visible_size = 256 << 20;
    let exchange = crate::amdgpu_vram_boot::Training {
        c2p: (12 << 30) - (9 << 20),
        p2c: (12 << 30) - 0x8000,
        size: 4096,
    };
    // SAFETY: bookkeeping-only pool; its GPU addresses are consistent
    // with the backed register mapping above.
    let pool = unsafe {
        Pool::from_owned_range(
            narf_bus::MmioRegion {
                phys: narf_memory::PhysAddr::new(0x9000_0000),
                virt: 0,
                len: 64 << 20,
                kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
            },
            0,
        )
    }
    .unwrap();
    let authority = Cap::bootstrap();
    let mut unfinished_firmware = firmware();
    unfinished_firmware.power = Some(crate::amdgpu_power_navi22::tests::prepared());
    let mut boot_firmware = firmware();
    boot_firmware.power = Some(crate::amdgpu_power_navi22::tests::prepared());
    // SAFETY: constructors perform no I/O; the trainer only allocates its
    // preimage/cache, and every step below refuses before touching the
    // device. No queue, display or service ever starts, so the missing
    // `quiesce_for_reset` cannot be observed: the rebuilt owner is never
    // run.
    let mut unfinished = unsafe {
        ColdBoot::new_with_training(
            &trained_gpu,
            authority,
            &pool,
            unfinished_firmware,
            exchange,
        )
    }
    .unwrap();
    // SAFETY: same constructor as `unfinished` above: no I/O, the trainer
    // only allocates its preimage/cache, and every step below refuses
    // before touching the device.
    let mut boot = unsafe {
        ColdBoot::new_with_training(&trained_gpu, authority, &pool, boot_firmware, exchange)
    }
    .unwrap();
    // A cold-path control: its finished trainer must cold-train (`run`),
    // not replay, when its owner has no reset to replay after.
    // SAFETY: same constructor as `unfinished` above: no I/O, the trainer
    // only allocates its preimage/cache, and every step below refuses
    // before touching the device.
    let mut cold = unsafe {
        ColdBoot::new_with_training(&trained_gpu, authority, &pool, firmware(), exchange)
    }
    .unwrap();
    for owner in [&mut unfinished, &mut boot] {
        // SAFETY: register reads are backed by the zeroed fixture regs and
        // the pool is the consistent aperture for them; each owner
        // exclusively owns its fixture-GPU snapshot, authority and pool
        // slice, and no other PSP owner exists in this test.
        let psp =
            unsafe { psp::Psp::new_rdna2(&owner.sequence.backend.gpu, authority, &pool) }.unwrap();
        owner.sequence.backend.psp = Some(psp);
        // SAFETY: forwarded whole-GPU/pool/PCI ownership from the owner;
        // no I/O or interrupt routing occurs during construction, and no
        // other IH owner exists in this test.
        let ih = unsafe {
            crate::amdgpu_ih_navi22::Ih::new_rdna2(
                &owner.sequence.backend.gpu,
                authority,
                &pool,
                device,
            )
        }
        .unwrap();
        owner.sequence.backend.ih = Some(ih);
        owner.sequence.state = State::FirmwareReady(report());
    }
    // A trainer that never finished cannot be replayed: the owner stays
    // unrecoverable and the rebuild is refused before any I/O.
    if unfinished.training_replayable() || unfinished.recoverable() {
        return TestResult::Fail("unfinished GDDR6 trainer left the owner recoverable");
    }
    // SAFETY: refused before any constructor or I/O runs.
    if unsafe { unfinished.into_recovery(device) }.err() != Some(Error::Busy) {
        return TestResult::Fail("rebuilt an owner with an unfinished GDDR6 trainer");
    }
    // The finished trainer makes the trained owner recoverable.
    boot.sequence
        .backend
        .training
        .as_mut()
        .unwrap()
        .mark_finished_for_test();
    cold.sequence
        .backend
        .training
        .as_mut()
        .unwrap()
        .mark_finished_for_test();
    if !boot.training_replayable()
        || !boot.recoverable()
        || boot.training_state() != Some(gddr6::State::Ready)
    {
        return TestResult::Fail("finished GDDR6 trainer left the owner unrecoverable");
    }
    // SAFETY: as above; the rebuilt owner is never run.
    let mut rebuilt = unsafe { boot.into_recovery(device) }.unwrap();
    if rebuilt.training_state() != Some(gddr6::State::Ready)
        || !rebuilt.sequence.backend.training_resume
        || !rebuilt.training_replayable()
    {
        return TestResult::Fail("recovery rebuild dropped the finished GDDR6 trainer");
    }
    // The replay runs at MemoryTraining, after the reset and before SOS:
    // revoke the trainer's authority so the probe fails at the cap invoke,
    // before any MMIO, and distinguishes replay (Revoked) from cold
    // training (Busy on a finished trainer).
    authority.revoke();
    if run(rebuilt.sequence.backend.step(Stage::MemoryTraining))
        != Err(Error::Training(gddr6::Error::Revoked))
    {
        return TestResult::Fail("rebuilt owner cold-trained instead of replaying its cache");
    }
    if run(cold.sequence.backend.step(Stage::MemoryTraining))
        != Err(Error::Training(gddr6::Error::Busy))
    {
        return TestResult::Fail("cold owner replayed instead of cold-training");
    }
    // A failed or cancelled replay wedges the trainer: it can no longer be
    // replayed, so the owner stays unrecoverable rather than rebuilding
    // onto untrained memory. The refused cold path wedges nothing.
    if rebuilt.training_replayable() || !cold.training_replayable() {
        return TestResult::Fail("failed GDDR6 replay left the trainer replayable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_trained_owner_survives_recovery_rebuild
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
        // GDDR6 replay order (#1796): the mode1 reset, then the training
        // replay, then SOS loads — a replay before the reset would train
        // state the reset discards, and after SOS would train under a
        // running bootloader.
        || at(Stage::ResetOnInit) + 1 != at(Stage::MemoryTraining)
        || at(Stage::MemoryTraining) + 1 != at(Stage::Sos)
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

/// Every display path that builds the VBIOS `Tables` routes them through
/// the running DMUB (`with_dmub(DmubRoute::new(..))`), as `modeset_display`
/// does; `retrain_display` and `stop_unplugged_display` built bare tables,
/// so with DMUB alive the ATOM interpreter raced the DMCUB's own table
/// execution (DCN3.0 `dmub_command_table` in command_table2.c).
fn navi22_display_tables_always_go_through_dmub() -> TestResult {
    let source = include_str!("amdgpu_navi22_boot.rs");
    let mut sites = 0;
    let mut rest = source;
    while let Some(at) = rest.find("amdgpu_navi22_bios::Tables::new(") {
        let tail = &rest[at..];
        // The builder chain ends at the statement's `;`.
        let chain = &tail[..tail.find(';').unwrap_or(tail.len())];
        if !chain.contains(".with_dmub(") {
            return TestResult::Fail("a display path builds VBIOS tables without the DMUB route");
        }
        sites += 1;
        rest = &tail[1..];
    }
    if sites < 4 {
        return TestResult::Fail("expected modeset/stop/retrain/unplug table sites");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-boot",
    navi22_display_tables_always_go_through_dmub
);

fn rdna2_coordinator_matches_all_firmware_before_bootstrap() -> TestResult {
    for profile in crate::amdgpu_rdna2::PROFILES {
        let make_firmware = || Firmware {
            sos: sos::tests::firmware_for(profile),
            smc: smu::tests::firmware_for(profile),
            graphics: gfx::tests::fixture_for(profile),
            power: None,
            dmub: None,
            display: None,
        };
        let mut gpu = crate::amdgpu_cp_navi22::tests::rdna2_gpu(profile, profile.pci_ids[0]);
        for block in &mut gpu.ip_blocks {
            if [
                crate::amdgpu_discovery::HW_ID_MP0,
                crate::amdgpu_discovery::HW_ID_MP1,
            ]
            .contains(&block.hw_id)
            {
                (block.major, block.minor, block.revision) = profile.psp_version;
            }
        }
        let pool = pool(16 << 20);
        let cap = Cap::bootstrap();
        cap.revoke();
        // SAFETY: inert mappings; revoked authority prevents device access.
        let mut boot = unsafe { ColdBoot::new_rdna2(&gpu, cap, &pool, make_firmware()) }.unwrap();
        if run(boot.run()) != Err(Error::Sos(sos::Error::Revoked)) {
            return TestResult::Fail(
                "family coordinator reached hardware without current authority",
            );
        }
        drop(boot);
        if pool.available() != 16 << 20 {
            return TestResult::Fail("unpublished bootstrap storage leaked");
        }
        if profile != &crate::amdgpu_rdna2::NAVI22 {
            // SAFETY: the native entry must refuse before device access.
            if unsafe { ColdBoot::new(&gpu, cap, &pool, make_firmware()) }.is_ok() {
                return TestResult::Fail("shared coordinator widened legacy native gate");
            }
            let mut wrong = make_firmware();
            wrong.graphics = gfx::tests::fixture();
            // SAFETY: typed image mismatch is rejected before device access.
            if unsafe { ColdBoot::new_rdna2(&gpu, cap, &pool, wrong) }.is_ok() {
                return TestResult::Fail("coordinator accepted firmware from another ASIC");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_coordinator_matches_all_firmware_before_bootstrap
);
