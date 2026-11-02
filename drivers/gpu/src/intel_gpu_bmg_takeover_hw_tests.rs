// Real capability/PCI/BAR view plus independent source hardware semantics.
// All storage is owned fixture RAM, never ECAM or a physical GPU. Every model
// access first executes the actual AuthorizedWindow per-raw guard. W1C/reset
// effects are then device-side oracle behavior, not injected host receipts.
use super::*;
use crate::intel_gpu_gt::lnl;
use crate::intel_gpu_gt_hw::{AuthorizedWindow, HardwareInit};
use crate::intel_gpu_rcs::{GgttArena, GpuAllocator, GpuBacking, SharedArena};
use core::cell::{Cell, RefCell};
use narf_capabilities::{Cap, Write};

// ECAM retains permanent mappings. Reuse one permanently owned RAM page rather
// than freeing a still-mapped frame or consuming one of its eight segment slots
// for every fault scenario. A nonblocking lease serializes these sync fixtures;
// no capability or register view from the previous owner remains current.
static CONFIG_PAGE: narf_lib::mutex::Mutex<Option<narf_memory::frame::PhysFrame>> =
    narf_lib::mutex::Mutex::new(None);

struct Physical {
    cfg: narf_memory::frame::PhysFrame,
    cfg_virt: u64,
    _cfg_lease: narf_lib::mutex::MutexGuard<'static, Option<narf_memory::frame::PhysFrame>>,
    words: Vec<u32>,
    local_words: Vec<u32>,
    device: narf_bus::BusDevice,
    bar: narf_bus::MmioRegion,
    local: narf_bus::MmioRegion,
    cap: Cap<narf_bus::BusDeviceCap, Write>,
    window: AuthorizedWindow,
    trace: RefCell<Vec<(bool, u64, u32)>>,
    flrs: Cell<usize>,
    w1cs: Cell<usize>,
    fail_w1c: Cell<Option<usize>>,
    hold_flr: Cell<bool>,
    hold_media: Cell<bool>,
    drop_trigger: Cell<bool>,
    loss_at: Cell<Option<usize>>,
    calls: Cell<usize>,
}
impl Physical {
    fn new(release: u32) -> Self {
        let mut cfg_lease = CONFIG_PAGE
            .try_lock()
            .expect("exclusive fake PCI config lease");
        let cfg = *cfg_lease.get_or_insert_with(|| narf_memory::frame::alloc_frame().unwrap());
        // SAFETY: this fixture holds the sole lease of the retained fake PCI
        // configuration page. The actual ECAM registry must map cfg_phys before
        // pci::read_config32/power_state and AuthorizedWindow can access it.
        // Re-registering the same page is idempotent, including after a bus
        // fixture has reset its mapping registry; the frame is never freed.
        assert!(unsafe { narf_bus::ecam::map_segment(cfg.start_address(), 4096) });
        let cfg_virt = narf_bus::ecam::va_for(cfg.start_address()).unwrap();
        // SAFETY: the held lease owns every byte of this mapped RAM page.
        // Both the fixture and real PCI helpers use the same mapped view.
        unsafe {
            core::ptr::write_bytes(cfg_virt as *mut u8, 0, 4096);
        }
        let mut words = alloc::vec![0u32; 4 * 1024 * 1024];
        let mut local_words = alloc::vec![0u32; BO as usize / 4];
        let mut device = source_device(0xe20b);
        if let narf_bus::BusKind::Pcie { cfg_phys, .. } = &mut device.kind {
            *cfg_phys = cfg.start_address();
        }
        let bar = narf_bus::MmioRegion {
            virt: words.as_mut_ptr() as u64,
            ..source_bar()
        };
        let local = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0x80000000),
            virt: local_words.as_mut_ptr() as u64,
            len: BO,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        let store_cfg = |offset: usize, value: u32| {
            // SAFETY: cfg owns this zeroed 4 KiB RAM configuration page;
            // every call below uses an aligned dword offset at most 0x44.
            unsafe { core::ptr::write_volatile((cfg_virt as *mut u32).add(offset / 4), value) }
        };
        store_cfg(0, 0xe20b8086);
        store_cfg(4, 0x00100006);
        store_cfg(8, 0x03000003);
        store_cfg(0x10, 0x10000004);
        store_cfg(0x14, 0);
        store_cfg(0x18, 0x8000000c);
        store_cfg(0x1c, 0);
        store_cfg(0x34, 0x40);
        store_cfg(0x40, 1);
        store_cfg(0x44, 0);
        words[0xd8c / 4] = (20 << 22) | release << 14;
        words[0x380d8c / 4] = (13 << 22) | (1 << 14);
        words[0x101018 / 4] = 0x80000000;
        words[0x38c000 / 4] = 1;
        words[0xc000 / 4] = 1;
        words[0xfd0 / 4] = 1;
        words[0xfd4 / 4] = 0x92340506;
        words[0x130030 / 4] = 0x91357731;
        let cap = Cap::<narf_bus::BusDeviceCap, Write>::bootstrap();
        assert_eq!(
            narf_bus::pci::read_config32(&cap, &device, 0),
            Ok(0xe20b8086)
        );
        assert_eq!(narf_bus::pci::read_command(&cap, &device), Ok(6));
        assert_eq!(
            narf_bus::pci::power_state(&cap, &device),
            Ok(Some(narf_bus::pci::PciPowerState::D0))
        );
        assert_eq!(narf_bus::pci::read_config32(&cap, &device, 0x100), Ok(0));
        let window = AuthorizedWindow::for_bmg_device(bar, cap, device, Some(local));
        assert!(window.current());
        Self {
            cfg,
            cfg_virt,
            _cfg_lease: cfg_lease,
            words,
            local_words,
            device,
            bar,
            local,
            cap,
            window,
            trace: RefCell::new(Vec::new()),
            flrs: Cell::new(0),
            w1cs: Cell::new(0),
            fail_w1c: Cell::new(None),
            hold_flr: Cell::new(false),
            hold_media: Cell::new(false),
            drop_trigger: Cell::new(false),
            loss_at: Cell::new(None),
            calls: Cell::new(0),
        }
    }
    fn set_cfg(&self, offset: usize, value: u32) {
        // SAFETY: fake config page stays owned for this fixture lifetime.
        unsafe { core::ptr::write_volatile((self.cfg_virt as *mut u32).add(offset / 4), value) }
    }
    fn load(&self, reg: u64) -> u32 {
        assert!(reg & 3 == 0 && reg < self.bar.len);
        // SAFETY: self.words retains the entire RAM BAR for self's lifetime;
        // the checked aligned offset selects a complete in-bounds dword.
        unsafe { core::ptr::read_volatile((self.bar.virt + reg) as *const u32) }
    }
    fn set(&self, reg: u64, value: u32) {
        assert!(reg & 3 == 0 && reg < self.bar.len);
        // SAFETY: independent device-side effects only in exclusive model RAM.
        unsafe { core::ptr::write_volatile((self.bar.virt + reg) as *mut u32, value) }
    }
    fn advance(&self) {
        let at = self.calls.get();
        self.calls.set(at + 1);
        if self.loss_at.get() == Some(at) {
            self.set_cfg(0x44, 3);
        }
    }
    fn no_pte(&self) -> bool {
        self.words[0x800000 / 4..].iter().all(|v| *v == 0)
    }
    fn takeover(&self) -> Takeover {
        Takeover::new(self.device, self.bar, self.local, 0).unwrap()
    }
    fn finish_takeover(&self) -> (Takeover, Arc<Authority>) {
        let mut takeover = self.takeover();
        for now in 0..32 {
            assert!(self.no_pte());
            match takeover.poll(self, now, || self.window.current()) {
                Poll::Pending => {}
                Poll::Ready(Ok(authority)) => return (takeover, authority),
                other => panic!("actual raw takeover: {other:?}"),
            }
        }
        panic!("bounded physical source preamble did not complete")
    }
}
impl MmioWindow for Physical {
    fn read32(&self, reg: u64) -> u32 {
        self.advance();
        let value = self.window.read32(reg);
        self.trace.borrow_mut().push((false, reg, value));
        value
    }
    fn write32(&self, reg: u64, value: u32) {
        self.advance();
        let old = self.load(reg);
        self.window.write32(reg, value);
        self.trace.borrow_mut().push((true, reg, value));
        if !self.window.current() {
            assert_eq!(self.load(reg), old);
            return;
        }
        match reg {
            0x101018 => {
                let count = self.w1cs.get() + 1;
                self.w1cs.set(count);
                self.set(
                    reg,
                    if self.fail_w1c.get() == Some(count) {
                        old
                    } else {
                        old & !value
                    },
                );
            }
            0x101010 if value & 0x80000000 != 0 => {
                assert!(self.no_pte());
                self.flrs.set(self.flrs.get() + 1);
                assert_eq!(self.load(0x101018) & 0x80000000, 0);
                for r in [
                    0xa188, 0xa278, 0xdfc, 0xd84, 0x38a188, 0x380dfc, 0x38941c, 0x38c314, 0xc314,
                    0x941c,
                ] {
                    self.set(r, 0);
                }
                self.set(0x38c000, 1);
                self.set(0xc000, 1);
                if self.drop_trigger.get() {
                    self.set(reg, old);
                } else if !self.hold_flr.get() {
                    self.set(reg, value & !0x80000000);
                    self.set(0x101018, 0x80000000);
                }
            }
            0x38a188 | 0xa188 | 0xa278 => {
                let actual = (old & !(value >> 16)) | (value & (value >> 16));
                self.set(reg, actual);
                let ack = match reg {
                    0x38a188 => 0x380dfc,
                    0xa188 => 0xdfc,
                    _ => 0xd84,
                };
                if reg != 0x38a188 || !self.hold_media.get() {
                    self.set(ack, actual & 1);
                }
            }
            0x38941c | 0x941c => {
                assert!(value == 8 || value == 1);
                self.set(reg, 0); // independent hardware reset self-clear
                let base = if reg == 0x38941c { 0x380000 } else { 0 };
                self.set(base + 0xc000, 1);
                self.set(base + 0xc314, 0);
            }
            _ => {}
        }
    }
}
impl Drop for Physical {
    fn drop(&mut self) {
        // Fake RAM has never started an engine. Revoke the real wrapper before
        // dropping this config lease/MMIO storage so no surviving view remains
        // current. ECAM mappings are permanent: CONFIG_PAGE retains the frame
        // for subsequent fixture leases instead of freeing still-mapped RAM.
        self.cap.revoke();
        assert_eq!(
            narf_bus::ecam::va_for(self.cfg.start_address()),
            Some(self.cfg_virt)
        );
        assert_eq!(self.local_words.len(), BO as usize / 4);
    }
}
fn smoke_bmg_smallbar_actual_pci_authority_and_no_integrated_read_wa() -> TestResult {
    for (offset, value) in [
        (0, 0xffff_ffff),
        (0, 0xe20b1234),
        (4, 0x00100002),
        (8, 0x02000003),
        (0x10, 0x11000004),
        (0x14, 1),
        (0x18, 0x9000000c),
        (0x1c, 1),
        (0x44, 3),
        (0x100, 0xffffffff),
        (0x100, 0x10010001),
    ] {
        let p = Physical::new(2);
        p.set_cfg(offset, value);
        assert!(!p.window.current());
        let before = p.load(0x4000);
        assert_eq!(p.window.read32(0x4000), u32::MAX);
        p.window.write32(0x4000, 0x12345678);
        assert_eq!(p.load(0x4000), before);
        assert_eq!(
            p.load(0x130030),
            0x91357731,
            "BMG must not import four-zero WA"
        );
        assert!(p.no_pte());
    }
    for (control, count) in [(1, 0), (0, 1)] {
        let p = Physical::new(2);
        p.set_cfg(0x100, 0x00010010);
        p.set_cfg(0x108, control);
        p.set_cfg(0x110, count);
        assert!(!p.window.current());
        assert!(p.no_pte());
    }
    let p = Physical::new(2);
    p.cap.revoke();
    assert!(!p.window.current());
    assert_eq!(p.window.read32(0x4000), u32::MAX);
    let before = p.load(0x4000);
    p.window.write32(0x4000, 0x1badc0de);
    assert_eq!(p.load(0x4000), before);
    assert!(p.no_pte());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_actual_pci_authority_and_no_integrated_read_wa
);
fn smoke_bmg_smallbar_actual_flr_media_and_first_cache_pte() -> TestResult {
    use narf_graphics::console::BootFramebufferAdmission;
    for release in [1, 2] {
        let mut boot = BootFramebufferAdmission::new();
        let mut console = BootFramebufferAdmission::new();
        assert!(boot.close_if_never(true) && console.close_if_never(true));
        assert!(!boot.publish() && !console.publish());
        let p = Physical::new(release);
        if release == 2 {
            p.set(0x10100c, 1 << 9);
            p.set(0x510a0, (14 << 22) | (1 << 14));
            p.set(0x42000, 0x0c000000);
            p.set(0x43288, u32::MAX);
            p.set(0x432c8, u32::MAX); // absent FBC C/D must not be read
        }
        let mut takeover = p.takeover();
        let authority = (0..32)
            .find_map(|now| {
                assert!(p.no_pte());
                match takeover.poll(&p, now, || {
                    p.window.current() && boot.is_closed() && console.is_closed()
                }) {
                    Poll::Pending => None,
                    Poll::Ready(Ok(proof)) => Some(proof),
                    other => panic!("source physical preamble: {other:?}"),
                }
            })
            .unwrap();
        assert_eq!(p.flrs.get(), 1);
        assert_eq!(p.w1cs.get(), 2);
        assert!(authority.current(&p.window).is_ok());
        let mut wrong = p.bar;
        wrong.len += 4096;
        assert!(GgttArena::for_smallbar_gt(wrong, p.window.clone(), authority.clone()).is_err());
        let mut wrong = p.bar;
        wrong.virt += 4096;
        assert!(GgttArena::for_smallbar_gt(wrong, p.window.clone(), authority.clone()).is_err());
        let mut arena = SharedArena::new(
            GgttArena::for_smallbar_gt(p.bar, p.window.clone(), authority.clone()).unwrap(),
        );
        let mut backing = arena.alloc(1).unwrap();
        assert!(p.no_pte());
        let pte = 0x800000 + u64::from(backing.ggtt_offset() / 4096) * 8;
        // Source fresh main forcewake and actual HardwareInit/reset/cache
        // conversation follows FLR/media retirement; no inherited cache flag.
        p.write32(0xa188, 0x00010001);
        let mut hardware = HardwareInit::new(GtPlatform::Battlemage).unwrap();
        hardware.begin(&p, 100).unwrap();
        assert!(hardware.poll(&p, 101).is_pending());
        assert!(p.no_pte());
        assert!(hardware.poll(&p, 102).is_pending());
        assert!(p.no_pte());
        let Poll::Ready(Ok(policy)) = hardware.poll(&p, 103) else {
            panic!("fresh source cache")
        };
        assert_eq!(p.load(0x4808), 0xf);
        assert_eq!(p.load(0x400c), 0x13c);
        assert!(p.no_pte());
        arena.configure_cache(&mut backing, policy).unwrap();
        let entry = u64::from(p.load(pte)) | u64::from(p.load(pte + 4)) << 32;
        assert_eq!(entry & 0xfff0000000000fff, 0x0020000000000001);
        // Plain RAM cannot implement readonly GMD writes. Restore the device's
        // immutable source identity after independently witnessing the required
        // BMG drain; real hardware ignores this write to its readonly register.
        assert_eq!(p.load(0xd8c), 0);
        p.set(0xd8c, (20 << 22) | release << 14);
        arena.free(backing);
        assert_eq!(p.load(pte), 0);
        assert_eq!(arena.live_allocations(), 0);
        p.set(0xd8c, (20 << 22) | release << 14);
        assert!(matches!(
            takeover.poll(&p, 10_000_000_000, || p.window.current()),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(p.flrs.get(), 1);
        assert_eq!(p.load(0x130030), 0x91357731);
        drop(arena);
        drop(authority);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_actual_flr_media_and_first_cache_pte
);
fn smoke_bmg_smallbar_actual_flr_faults_and_no_pte_before_every_proof() -> TestResult {
    for scenario in 0..9 {
        let p = Physical::new(2);
        match scenario {
            0 => p.set(0x10100c, 0x80000000),
            1 => p.fail_w1c.set(Some(1)),
            2 => p.hold_flr.set(true),
            3 => p.drop_trigger.set(true),
            4 => p.fail_w1c.set(Some(2)),
            5 => p.hold_media.set(true),
            6 => p.set(0x380d8c, 20 << 22),
            7 => {
                p.set(0x10100c, 1 << 9);
                p.set(0x510a0, (14 << 22) | (2 << 14));
            }
            8 => {
                p.set(0x10100c, 1 << 9);
                p.set(0x510a0, (14 << 22) | (1 << 14));
                p.set(0x42000, 0x0c000000);
                p.set(0x43208, 0x80000000);
            }
            _ => unreachable!(),
        }
        let mut takeover = p.takeover();
        let mut failure = false;
        for now in [0, 1, 2, 3, 4, 5, 50_000_006, 3_000_000_001, 6_000_000_002] {
            match takeover.poll(&p, now, || p.window.current()) {
                Poll::Pending => {}
                Poll::Ready(Err(_)) => {
                    failure = true;
                    break;
                }
                Poll::Ready(Ok(_)) => panic!("failed source proof minted a receipt"),
            }
            assert!(p.no_pte());
        }
        assert!(failure);
        assert!(p.no_pte());
    }
    let baseline = Physical::new(2);
    let (owner, authority) = baseline.finish_takeover();
    let calls = baseline.calls.get();
    drop(authority);
    drop(owner);
    drop(baseline);
    // Authority is lost before each independently authorized source raw access,
    // including clear/trigger/completion and media wake/reset/identity reads.
    for at in 0..calls {
        let p = Physical::new(2);
        p.loss_at.set(Some(at));
        let mut takeover = p.takeover();
        let mut failed = false;
        for now in 0..32 {
            match takeover.poll(&p, now, || p.window.current()) {
                Poll::Pending => {}
                Poll::Ready(Err(_)) => {
                    failed = true;
                    break;
                }
                Poll::Ready(Ok(_)) => panic!("current loss admitted source receipt at{at}"),
            }
        }
        assert!(failed);
        assert!(p.no_pte());
    }
    // Application arguments cannot even begin the destructive source preamble.
    let p = Physical::new(2);
    assert!(!smallbar::requested(narf_boot::args::KernelCmdline::new(
        "-- narf.intel.bmg_smallbar=1"
    )));
    assert_eq!(p.flrs.get(), 0);
    assert!(p.trace.borrow().is_empty());
    assert!(p.no_pte());
    let mut prior = narf_graphics::console::BootFramebufferAdmission::new();
    assert!(prior.publish());
    assert!(!prior.close_if_never(true));
    let mut takeover = p.takeover();
    assert!(matches!(
        takeover.poll(&p, 0, || prior.is_closed() && p.window.current()),
        Poll::Ready(Err(lnl::Error::Unavailable))
    ));
    assert!(p.trace.borrow().is_empty());
    assert!(p.no_pte());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_smallbar",
    smoke_bmg_smallbar_actual_flr_faults_and_no_pte_before_every_proof
);
