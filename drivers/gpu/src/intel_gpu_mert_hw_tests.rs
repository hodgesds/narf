// Source-cited native production lifecycle, not extracted Linux execution.
// MIT Linux b90c984d xe_gt.c host-L2, xe_device.c GLOBAL_INVAL,
// xe_guc_pc.c bootstrap/sanitize/unload and xe_wa_oob.rules20.01 PF.
use crate::intel_gpu_guc_sched::SchedulingError;
use crate::intel_gpu_power_controls::PowerControls;
use crate::intel_gpu_slpc::{FrequencyRange, SlpcError, SlpcState};
use core::cell::Cell;
use narf_filesystem::{sysfs::Kobject, FsError};

struct Registers {
    armed: bool,
    held: bool,
    busy: bool,
    selector: u32,
    host: u32,
    clos: u32,
    actual: u32,
    rp: u32,
    request: u32,
    flush: bool,
    finish_flush: bool,
    follow_manual: bool,
    reject: Option<u64>,
    absent: Option<u64>,
    flushes: usize,
    accesses: Vec<(bool, u64, u32)>,
}
impl Default for Registers {
    fn default() -> Self {
        Self {
            armed: false,
            held: false,
            busy: false,
            selector: 0x92340506,
            host: 0x12340011,
            clos: 0x87543000,
            actual: 128,
            rp: 0x12340123,
            request: 0x00456789,
            flush: false,
            finish_flush: true,
            follow_manual: true,
            reject: None,
            absent: None,
            flushes: 0,
            accesses: Vec::new(),
        }
    }
}
#[derive(Clone)]
struct Io {
    inner: Window,
    regs: Rc<RefCell<Registers>>,
}
impl MmioWindow for Io {
    fn read32(&self, reg: u64) -> u32 {
        if !self.regs.borrow().armed {
            return self.inner.read32(reg);
        }
        let mut r = self.regs.borrow_mut();
        let value = if r.absent == Some(reg) {
            u32::MAX
        } else {
            match reg {
                0xfd0 => {
                    if r.busy {
                        0
                    } else {
                        assert!(!r.held);
                        r.held = true;
                        1
                    }
                }
                0xfd4 => {
                    assert!(r.held);
                    r.selector
                }
                0x4194 => {
                    assert!(r.held);
                    assert_eq!(r.selector & 0xf0f, 0);
                    r.host
                }
                0xb1ac => {
                    assert!(r.held);
                    assert_eq!(r.selector & 0xf0f, 0);
                    r.clos
                }
                0xc60 => r.actual,
                0xa024 => r.rp,
                0xa008 => r.request,
                0xb404 => {
                    if r.flush && r.finish_flush {
                        r.flush = false;
                    }
                    u32::from(r.flush)
                }
                _ => {
                    drop(r);
                    return self.inner.read32(reg);
                }
            }
        };
        r.accesses.push((false, reg, value));
        value
    }
    fn write32(&self, reg: u64, value: u32) {
        if !self.regs.borrow().armed {
            self.inner.write32(reg, value);
            return;
        }
        let mut r = self.regs.borrow_mut();
        r.accesses.push((true, reg, value));
        if r.reject == Some(reg) {
            return;
        }
        match reg {
            0xfd0 => {
                assert!(r.held);
                assert_eq!(value, 1);
                r.held = false;
            }
            0xfd4 => {
                assert!(r.held);
                r.selector = value;
            }
            0x4194 => {
                assert!(r.held);
                assert_ne!(r.selector & 0x80000000, 0);
                r.host = value;
            }
            0xb1ac => {
                assert!(r.held);
                assert_ne!(r.selector & 0x80000000, 0);
                r.clos = value;
            }
            0xb404 => {
                assert_eq!(value, 1);
                assert!(!r.flush);
                r.flush = true;
                r.flushes += 1;
            }
            0xa024 => r.rp = value,
            0xa008 => {
                assert_eq!(r.rp & 0x600, 0x400);
                r.request = value;
                if r.follow_manual {
                    r.actual = value >> 23;
                }
            }
            _ => {}
        }
        drop(r);
        self.inner.write32(reg, value);
    }
}
struct Rig {
    io: Io,
    arena: Arena,
    gt: GuCGt<Io, Arena>,
    registered: BTreeMap<u32, u32>,
    now: u64,
    epoch: u64,
}
impl Rig {
    fn new(release: u32, mode: u32) -> Self {
        let (inner, arena) = model();
        inner.0.borrow_mut().regs.extend([
            (0xdfc, 0),
            (0xa188, 2),
            (0xa278, 2),
            (0xd84, 0),
            (0xfd0, 1),
            (0x913c, 5),
            (0x9144, 6),
            (0x9134, 5),
            (0x9114, 0x10),
            (0x9118, 1),
            (0x138000, (18 << 16) | 180),
            (0x13800c, 90),
            (0x145998, (6 << 16) | 60),
            (0x145ef0, 30 << 8),
            (0xd8c, (20 << 22) | (release << 14)),
        ]);
        let io = Io {
            inner,
            regs: Rc::new(RefCell::new(Registers::default())),
        };
        let boot = GuCBoot::stage_image(
            io.clone(),
            arena.clone(),
            GtPlatform::Battlemage,
            CssImage::parse(&image(), 70).unwrap(),
            BootConfig {
                device_id: 0xe20b,
                revision: 3,
                huc_upload_bytes: 0,
                uncached_mocs: Some(3),
            },
        )
        .unwrap();
        let mut gt = GuCGt::from_staged_hardware(boot).unwrap();
        hardware_discovery(&mut gt, &io.inner, 0xdfc);
        hardware_scheduling(&mut gt, &io.inner);
        let completion = gt.begin_context_defaults(26).unwrap();
        let mut registered = BTreeMap::new();
        for now in 27..300 {
            service_contexts(&io.inner, &mut registered, true);
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            if completion.result().is_some() {
                break;
            }
        }
        assert_eq!(completion.result(), Some(Ok(())));
        let epoch = gt.user_epoch().unwrap();
        SLPC_FIXTURE_MODE.store(mode, core::sync::atomic::Ordering::Relaxed);
        gt.begin_slpc(1000).unwrap();
        for now in 1001..1050 {
            service_contexts(&io.inner, &mut registered, true);
            assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
            if matches!(gt.slpc(), SlpcState::Running | SlpcState::Unavailable) {
                break;
            }
        }
        io.regs.borrow_mut().armed = true;
        Self {
            io,
            arena,
            gt,
            registered,
            now: 2000,
            epoch,
        }
    }
    fn tick(&mut self) {
        service_contexts(&self.io.inner, &mut self.registered, true);
        assert_eq!(
            self.gt.poll_with_access(self.now, || true),
            Poll::Ready(Ok(GtState::SchedulingReady))
        );
        self.now += 10000;
    }
    fn prepare(&mut self) {
        for _ in 0..64 {
            let done = self.gt.prepare_mert(self.now, || true).unwrap();
            self.tick();
            if done {
                return;
            }
        }
        panic!("bounded MERT sanitize did not finish");
    }
    fn reset_to_mert(&mut self) {
        self.now = self.now.max(2_000_000_000).saturating_add(1_000_000_000);
        self.gt.begin_stop(self.now).unwrap();
        for offset in 1..=8 {
            if offset > 1 || self.gt.state() == GtState::ResettingEngines {
                reset_done(&self.io.inner);
            }
            assert!(self.gt.poll(self.now + offset).is_pending());
            if matches!(
                self.gt.state(),
                GtState::StoppingMert | GtState::ReleasingRender
            ) {
                self.io.regs.borrow_mut().flush = false; // full reset cancels old request
                self.now += offset + 1;
                return;
            }
        }
        panic!("execution reset did not reach postreset handoff");
    }
    fn stop(mut self) {
        self.reset_to_mert();
        for _ in 0..32 {
            match self.gt.state() {
                GtState::ReleasingRender => {
                    self.io.inner.0.borrow_mut().regs.insert(0xd84, 0);
                }
                GtState::Releasing => {
                    self.io.inner.0.borrow_mut().regs.insert(0xdfc, 0);
                }
                GtState::Stopped => break,
                _ => {}
            }
            assert!(!matches!(
                self.gt.poll_with_access(self.now, || true),
                Poll::Ready(Err(_))
            ));
            self.now += 100_000;
        }
        assert_eq!(self.gt.state(), GtState::Stopped);
        assert_eq!(self.io.regs.borrow().host & 64, 0);
        assert!(!self.io.regs.borrow().held);
        drop(self.gt);
        assert_eq!(self.arena.live_allocations(), 0);
    }
}
struct Admin(Option<fn(u32) -> bool>);
impl Admin {
    fn set(allow: bool) -> Self {
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            if allow { |cap| cap == 21 } else { |_| false },
        )))
    }
}
impl Drop for Admin {
    fn drop(&mut self) {
        narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}

fn smoke_mert_real_gt_sysfs_sanitize_fused_bounds_and_host_flush() -> TestResult {
    let mut rig = Rig::new(1, 0);
    assert!(
        !rig.gt.vram_cpu_access(rig.epoch),
        "raw GT has no implicit host-L2 proof"
    );
    assert!(rig.gt.begin_vram_flush(rig.epoch, rig.now).is_err());
    let control = Arc::new(PowerControls::new());
    control.activate(rig.epoch);
    control.service(&mut rig.gt, rig.epoch, rig.now);
    let node = Kobject::new_root("mert-power");
    crate::intel_gpu_power_controls::fixture_attributes(&node, control.clone());
    let _admin = Admin::set(true);
    assert_eq!(node.attr_show("gt_max_freq_mhz").unwrap(), "2133\n");
    assert_eq!(
        node.attr_store("gt_max_freq_mhz", b"2800"),
        Some(Err(FsError::InvalidData))
    );
    rig.prepare();
    assert_eq!(
        rig.gt.slpc_status().unwrap().range,
        FrequencyRange {
            min_mhz: 1200,
            max_mhz: 3000
        }
    );
    assert_eq!(rig.gt.slpc_status().unwrap().limits.max_mhz, 3000);
    assert_eq!(rig.io.regs.borrow().host, 0x12340051);
    assert_eq!(rig.io.regs.borrow().clos, 0xf);
    assert_eq!(rig.io.regs.borrow().selector, 0x92340506);
    assert!(!rig.io.regs.borrow().held);
    control.service(&mut rig.gt, rig.epoch, rig.now);
    {
        let _deny = Admin::set(false);
        assert_eq!(
            node.attr_store("gt_max_freq_mhz", b"2800"),
            Some(Err(FsError::OperationNotPermitted))
        );
    }
    let accesses = rig.io.regs.borrow().accesses.len();
    assert_eq!(node.attr_store("gt_max_freq_mhz", b"2800"), Some(Ok(())));
    assert_eq!(
        rig.io.regs.borrow().accesses.len(),
        accesses,
        "sysfs performed MMIO"
    );
    for _ in 0..32 {
        control.service(&mut rig.gt, rig.epoch, rig.now);
        rig.tick();
    }
    assert_eq!(node.attr_show("gt_max_freq_mhz").unwrap(), "2800\n");
    assert_eq!(node.attr_store("gt_min_freq_mhz", b"2700"), Some(Ok(())));
    for _ in 0..32 {
        control.service(&mut rig.gt, rig.epoch, rig.now);
        rig.tick();
    }
    assert_eq!(
        node.attr_show("slpc_frequency_range").unwrap(),
        "2700 2800\n"
    );
    assert_eq!(
        node.attr_store("gt_max_freq_mhz", b"3001"),
        Some(Err(FsError::InvalidData))
    );
    rig.io.regs.borrow_mut().actual = 168; //2800MHz: no invented2600MHz/TDF cap
    let id = rig.gt.begin_vram_flush(rig.epoch, rig.now).unwrap();
    rig.tick();
    assert!(!rig.gt.vram_flush_done(rig.epoch, id).unwrap());
    rig.tick();
    assert!(rig.gt.vram_flush_done(rig.epoch, id).unwrap());
    assert!(rig
        .io
        .regs
        .borrow()
        .accesses
        .iter()
        .all(|(_, reg, _)| ![0xb418, 0xa008, 0xa024].contains(reg)));
    assert!(rig
        .io
        .inner
        .0
        .borrow()
        .writes
        .iter()
        .all(|(reg, _)| ![0x138124, 0x138128, 0x13812c].contains(reg)));
    control.close();
    assert!(node.attr_show("gt_max_freq_mhz").unwrap().is_empty());
    rig.stop();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_real_gt_sysfs_sanitize_fused_bounds_and_host_flush
);

fn smoke_mert_flush_tickets_cancel_backpressure_and_epoch_do_not_replay() -> TestResult {
    let mut rig = Rig::new(1, 0);
    rig.prepare();
    rig.io.regs.borrow_mut().finish_flush = false;
    let first = rig.gt.begin_vram_flush(rig.epoch, rig.now).unwrap();
    rig.tick();
    assert!(!rig.gt.idle());
    assert_eq!(
        rig.gt.begin_vram_flush(rig.epoch, rig.now),
        Err(GtError::Scheduling(SchedulingError::Slpc(SlpcError::Busy)))
    );
    let count = rig.io.regs.borrow().flushes;
    // The original waiter is gone. Only retained GT polling drains its post.
    rig.io.regs.borrow_mut().finish_flush = true;
    rig.tick();
    assert!(rig.gt.vram_flush_done(rig.epoch, first).unwrap());
    let second = rig.gt.begin_vram_flush(rig.epoch, rig.now).unwrap();
    assert_ne!(first, second);
    assert!(!rig.gt.vram_flush_done(rig.epoch, second).unwrap());
    rig.tick();
    assert_eq!(rig.io.regs.borrow().flushes, count + 1);
    assert!(!rig.gt.vram_flush_done(rig.epoch, second).unwrap());
    rig.tick();
    assert!(rig.gt.vram_flush_done(rig.epoch, second).unwrap());
    assert!(rig.gt.vram_flush_done(rig.epoch, first).unwrap());
    let accesses = rig.io.regs.borrow().accesses.len();
    assert!(rig.gt.begin_vram_flush(rig.epoch + 1, rig.now).is_err());
    assert!(rig.gt.vram_flush_done(rig.epoch + 1, second).is_err());
    assert_eq!(rig.io.regs.borrow().accesses.len(), accesses);
    rig.gt.begin_vram_flush(rig.epoch, rig.now).unwrap();
    rig.tick();
    rig.stop();
    let mut fresh = Rig::new(1, 0);
    assert_eq!(fresh.gt.slpc_status().unwrap().limits.max_mhz, 2133);
    assert_eq!(fresh.io.regs.borrow().host & 64, 0);
    fresh.prepare();
    assert_eq!(fresh.gt.slpc_status().unwrap().range.max_mhz, 3000);
    fresh.stop();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_flush_tickets_cancel_backpressure_and_epoch_do_not_replay
);

fn smoke_mert_qualified_optional_slpc_failure_refuses_vram_and_sanitize() -> TestResult {
    for mode in [1, 2] {
        let mut rig = Rig::new(1, mode);
        assert_eq!(rig.gt.slpc(), SlpcState::Unavailable);
        assert_eq!(
            rig.gt.prepare_mert(rig.now, || true),
            Err(GtError::Scheduling(SchedulingError::Slpc(
                SlpcError::Unavailable
            )))
        );
        assert!(!rig.gt.vram_cpu_access(rig.epoch));
        assert!(rig.gt.begin_vram_flush(rig.epoch, rig.now).is_err());
        assert_eq!(rig.io.regs.borrow().host & 64, 0);
        assert_eq!(rig.io.regs.borrow().flushes, 0);
        rig.stop();
    }
    let mut other = Rig::new(2, 1);
    assert!(other.gt.prepare_mert(other.now, || true).unwrap());
    assert_eq!(other.io.regs.borrow().flushes, 0);
    other.stop();
    SLPC_FIXTURE_MODE.store(0, core::sync::atomic::Ordering::Relaxed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_qualified_optional_slpc_failure_refuses_vram_and_sanitize
);

fn smoke_mert_bootstrap_actual_semaphore_and_flush_fail_closed() -> TestResult {
    for failure in 0..3 {
        let mut rig = Rig::new(1, 0);
        match failure {
            0 => rig.io.regs.borrow_mut().actual = 180,
            1 => rig.io.regs.borrow_mut().busy = true,
            _ => rig.io.regs.borrow_mut().finish_flush = false,
        }
        for _ in 0..4 {
            assert!(!rig.gt.prepare_mert(rig.now, || true).unwrap());
            rig.tick();
        }
        rig.now += 101_000_000;
        assert_eq!(
            rig.gt.prepare_mert(rig.now, || true),
            Err(GtError::Scheduling(SchedulingError::Slpc(
                SlpcError::Timeout
            )))
        );
        assert_eq!(rig.gt.slpc_status().unwrap().limits.max_mhz, 2133);
        assert_eq!(rig.gt.slpc_status().unwrap().range.max_mhz, 2133);
        rig.io.regs.borrow_mut().actual = 128;
        rig.io.regs.borrow_mut().busy = false;
        rig.io.regs.borrow_mut().finish_flush = true;
        rig.stop();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_bootstrap_actual_semaphore_and_flush_fail_closed
);

fn smoke_mert_current_authority_and_mcr_identity_before_every_access() -> TestResult {
    let mut rig = Rig::new(1, 0);
    let accesses = rig.io.inner.0.borrow().mmio_reads.get();
    {
        let _borrow = rig.io.inner.0.borrow_mut();
        assert_eq!(
            rig.gt.prepare_mert(rig.now, || false),
            Err(GtError::Unavailable)
        );
    }
    assert_eq!(rig.io.inner.0.borrow().mmio_reads.get(), accesses);
    rig.prepare();
    rig.gt.begin_vram_flush(rig.epoch, rig.now).unwrap();
    rig.io.regs.borrow_mut().host &= !64;
    assert_eq!(
        rig.gt.poll_with_access(rig.now, || true),
        Poll::Ready(Err(GtError::Scheduling(SchedulingError::Slpc(
            SlpcError::Unavailable
        ))))
    );
    assert_eq!(
        rig.io.regs.borrow().flushes,
        1,
        "bad live identity posted flush"
    );
    rig.stop();
    // Check denial after a successful target access too: no later MMIO may
    // escape the sticky current-access latch during its derived RMW/cleanup.
    let mut rig = Rig::new(1, 0);
    assert!(!rig.gt.prepare_mert(rig.now, || true).unwrap());
    let count = Cell::new(0);
    let allowed = || {
        let n = count.get();
        count.set(n + 1);
        n < 40
    };
    let result = rig.gt.prepare_mert(rig.now + 1, allowed);
    assert!(result.is_err());
    assert_eq!(rig.gt.slpc_status().unwrap().limits.max_mhz, 2133);
    // A full reset releases a previously acquired firmware steering lock.
    rig.io.regs.borrow_mut().held = false;
    rig.stop();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_current_authority_and_mcr_identity_before_every_access
);

fn smoke_mert_postreset_manual_settle_actual_timeout_retains_wake() -> TestResult {
    let mut rig = Rig::new(1, 0);
    rig.prepare();
    let (_, fence) = rig.gt.submit_kernel_probe(rig.now).unwrap();
    rig.io.regs.borrow_mut().follow_manual = false;
    rig.io.regs.borrow_mut().actual = 180;
    rig.reset_to_mert();
    assert_eq!(
        fence.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert_eq!(rig.gt.state(), GtState::StoppingMert);
    let retained = rig.arena.live_allocations();
    assert!(rig.gt.poll(rig.now).is_pending());
    assert_eq!(rig.io.regs.borrow().request, (90 << 23) | 0x00456789);
    assert_eq!(rig.io.regs.borrow().rp & 0x600, 0x400);
    assert!(rig.gt.poll(rig.now + 99_999).is_pending());
    assert_eq!(rig.io.regs.borrow().rp & 0x600, 0x400);
    assert!(rig.gt.poll(rig.now + 100_000).is_pending());
    assert_eq!(rig.io.regs.borrow().rp, 0x12340123);
    assert!(
        rig.gt.poll(rig.now + 10_000_000).is_pending(),
        "old5ms reset deadline leaked into actual-frequency wait"
    );
    assert_eq!(
        rig.gt.poll(rig.now + 100_100_000),
        Poll::Ready(Err(GtError::Scheduling(SchedulingError::Slpc(
            SlpcError::Timeout
        ))))
    );
    assert_eq!(rig.io.regs.borrow().host & 64, 64);
    assert_ne!(rig.io.inner.0.borrow().regs[&0xa188] & 1, 0);
    assert_ne!(rig.io.inner.0.borrow().regs[&0xa278] & 1, 0);
    assert_eq!(
        rig.arena.live_allocations(),
        retained,
        "uncertain host lease freed retained firmware"
    );
    rig.io.regs.borrow_mut().follow_manual = true;
    rig.stop(); // fresh full reset is required before retrying the handoff
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_postreset_manual_settle_actual_timeout_retains_wake
);

struct ClearPool {
    frame: narf_memory::frame::PhysFrame,
    pool: Arc<crate::intel_gpu_vram::Vram>,
    pointer: *mut u8,
}
impl ClearPool {
    fn new() -> Self {
        let frame = narf_memory::frame::alloc_pages_on(0, 6).unwrap();
        let pointer = frame.start_address().kernel_mut_ptr::<u8>();
        let bar = narf_bus::MmioRegion {
            phys: frame.start_address(),
            virt: pointer as u64,
            len: 4 * 65536,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: these exclusive fixture frames model the retained WC BAR.
        unsafe { core::ptr::write_bytes(pointer, 0xa5, bar.len as usize) };
        let layout = crate::intel_gpu_vram::VramLayout {
            tile_size: bar.len,
            tile_offset: 0,
            usable: bar.len,
        };
        // SAFETY: only this fixture's pool allocates from this RAM aperture.
        let pool = unsafe { crate::intel_gpu_vram::Vram::new(bar, layout) }.unwrap();
        Self {
            frame,
            pool,
            pointer,
        }
    }
}
impl Drop for ClearPool {
    fn drop(&mut self) {
        assert_eq!(self.pool.used(), 0, "unproven VRAM owner released");
        narf_memory::frame::free_pages(self.frame, 6);
    }
}

fn smoke_mert_cpu_clear_cancel_partial_ready_and_busy_retain_target() -> TestResult {
    for ready in [false, true] {
        let mut rig = Rig::new(1, 0);
        rig.prepare();
        let memory = ClearPool::new();
        let gem = crate::intel_gpu_gem::GemState::new();
        let pending = gem.prepare_vram(2 * 65536, None, &memory.pool).unwrap();
        let object = pending.object();
        let weak = Arc::downgrade(&object);
        let mut clear = object.begin_cpu_vram_clear().unwrap();
        let lease = rig
            .gt
            .retain_cpu_vram_clear(object.clone(), rig.epoch, rig.now)
            .unwrap()
            .unwrap();
        let terminal = lease.completion();
        assert!(!rig.gt.idle());
        let count = rig.io.regs.borrow().flushes;
        rig.tick();
        assert_eq!(rig.io.regs.borrow().flushes, count, "active writer flushed");
        let other = gem.prepare_vram(4096, None, &memory.pool).unwrap();
        assert!(matches!(
            rig.gt
                .retain_cpu_vram_clear(other.object(), rig.epoch, rig.now),
            Err(GtError::Scheduling(SchedulingError::Slpc(SlpcError::Busy)))
        ));
        assert!(rig
            .gt
            .retain_cpu_vram_clear(other.object(), rig.epoch + 1, rig.now)
            .is_err());
        drop(other); // No BAR write was admitted for the Busy transaction.
        assert_eq!(memory.pool.used(), 2 * 65536);
        // SAFETY: this actual GT lease precedes the first fixture BAR store;
        // the model owns the aperture and its live D0/wake/epoch proof.
        assert!(unsafe { clear.clear_next() }.is_none());
        // SAFETY: this poll cannot overlap a writer; the RAM remains retained.
        let bytes = unsafe { core::slice::from_raw_parts(memory.pointer, 4 * 65536) };
        assert!(bytes[..65536].iter().all(|byte| *byte == 0));
        assert!(bytes[65536..].iter().all(|byte| *byte == 0xa5));
        if ready {
            // SAFETY: the same retained model ownership covers the final chunk.
            assert!(unsafe { clear.clear_next() }.is_some());
            lease.ready();
        }
        drop(clear);
        drop(object);
        drop(pending);
        drop(lease); // Partial cancellation must initiate its own fresh flush.
        assert!(weak.upgrade().is_some());
        assert!(
            terminal.result().is_none(),
            "PM hold completed on caller Drop"
        );
        rig.io.regs.borrow_mut().finish_flush = false;
        rig.tick();
        assert_eq!(rig.io.regs.borrow().flushes, count + 1);
        assert_eq!(memory.pool.used(), 2 * 65536);
        assert!(terminal.result().is_none());
        assert!(rig.gt.begin_vram_flush(rig.epoch, rig.now).is_err());
        rig.io.regs.borrow_mut().finish_flush = true;
        rig.tick();
        assert_eq!(terminal.result(), Some(Ok(())));
        assert!(weak.upgrade().is_none());
        assert_eq!(memory.pool.used(), 0);
        rig.stop();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_cpu_clear_cancel_partial_ready_and_busy_retain_target
);

fn smoke_mert_cpu_clear_timeout_retains_until_postreset_l2_shutdown() -> TestResult {
    let mut rig = Rig::new(1, 0);
    rig.prepare();
    let memory = ClearPool::new();
    let gem = crate::intel_gpu_gem::GemState::new();
    let pending = gem.prepare_vram(2 * 65536, None, &memory.pool).unwrap();
    let object = pending.object();
    let weak = Arc::downgrade(&object);
    let mut clear = object.begin_cpu_vram_clear().unwrap();
    let lease = rig
        .gt
        .retain_cpu_vram_clear(object.clone(), rig.epoch, rig.now)
        .unwrap()
        .unwrap();
    let terminal = lease.completion();
    // SAFETY: the actual live model lease owns the private aperture and wakes.
    assert!(unsafe { clear.clear_next() }.is_none());
    drop(clear);
    drop(object);
    drop(pending);
    drop(lease);
    rig.io.regs.borrow_mut().finish_flush = false;
    rig.tick();
    rig.now += 1_000_001;
    assert_eq!(
        rig.gt.poll_with_access(rig.now, || true),
        Poll::Ready(Err(GtError::Scheduling(SchedulingError::Slpc(
            SlpcError::Timeout
        ))))
    );
    assert!(terminal.result().is_none());
    assert!(weak.upgrade().is_some());
    rig.io.regs.borrow_mut().finish_flush = true;
    rig.io.regs.borrow_mut().follow_manual = false;
    rig.io.regs.borrow_mut().actual = 180;
    rig.reset_to_mert();
    assert_eq!(rig.gt.state(), GtState::StoppingMert);
    assert!(
        terminal.result().is_none(),
        "execution reset released PM hold"
    );
    assert_eq!(memory.pool.used(), 2 * 65536);
    assert!(rig.gt.poll(rig.now).is_pending());
    assert!(rig.gt.poll(rig.now + 100_000).is_pending());
    assert_eq!(
        rig.gt.poll(rig.now + 100_100_000),
        Poll::Ready(Err(GtError::Scheduling(SchedulingError::Slpc(
            SlpcError::Timeout
        ))))
    );
    assert!(terminal.result().is_none());
    assert!(weak.upgrade().is_some());
    rig.io.regs.borrow_mut().follow_manual = true;
    rig.stop();
    assert_eq!(
        terminal.result(),
        Some(Err(crate::intel_gpu_fence::JobError::Reset))
    );
    assert!(weak.upgrade().is_none());
    assert_eq!(memory.pool.used(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_cpu_clear_timeout_retains_until_postreset_l2_shutdown
);

fn smoke_mert_cpu_clear_lost_gt_drop_retains_bo_and_pm_fence() -> TestResult {
    let mut rig = Rig::new(1, 0);
    rig.prepare();
    let memory = ClearPool::new();
    let pending = crate::intel_gpu_gem::GemState::new()
        .prepare_vram(2 * 65536, None, &memory.pool)
        .unwrap();
    let object = pending.object();
    let weak = Arc::downgrade(&object);
    let mut clear = object.begin_cpu_vram_clear().unwrap();
    let lease = rig
        .gt
        .retain_cpu_vram_clear(object.clone(), rig.epoch, rig.now)
        .unwrap()
        .unwrap();
    let terminal = lease.completion();
    // SAFETY: actual model GT ownership precedes this first private BAR chunk.
    assert!(unsafe { clear.clear_next() }.is_none());
    drop(clear);
    drop(object);
    drop(pending);
    drop(lease);
    assert_eq!(
        rig.gt.poll_with_access(rig.now, || false),
        Poll::Ready(Err(GtError::Unavailable))
    );
    drop(rig); // Lost GuCGt must leak all uncertain Parts, including the lease.
    assert!(weak.upgrade().is_some());
    assert!(terminal.result().is_none());
    assert_eq!(memory.pool.used(), 2 * 65536);
    // Deliberately retain this one fixture aperture: production likewise has
    // no reclamation proof after a lost GT is abandoned without reset.
    core::mem::forget(memory);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    smoke_mert_cpu_clear_lost_gt_drop_retains_bo_and_pm_fence
);
