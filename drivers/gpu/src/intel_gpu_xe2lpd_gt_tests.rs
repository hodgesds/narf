//! Lunar Lake display-preserving GT owner fixtures (§17 10.5). Expected
//! values are worked by hand from Linux b90c984d (xe_device.c, xe_gt.c,
//! xe_guc.c, xe_regs.h, xe_gt_regs.h, intel_display_device.c,
//! intel_dmc_regs.h, intel_dsb_regs.h, intel_cursor_regs.h); register
//! literals are repeated independently of the production constants.
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::{
    lnl::{DriverFlr, Error, Receipt},
    GtPlatform,
};
use crate::intel_gpu_gt_runtime::{lnl_profile, system_suspend_admitted, LnlProfile};
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use core::task::Poll;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A register file whose writes are logged and stored, except `GU_DEBUG`
/// (0x101018), which is write-one-to-clear unless `sticky`, and the GDRST
/// registers (0x941c, 0x38941c), which self-clear when `self_clear`.
#[derive(Default)]
struct Regs {
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    reads: Cell<usize>,
    sticky: Cell<bool>,
    self_clear: Cell<bool>,
}

impl Regs {
    fn with(values: &[(u64, u32)]) -> Self {
        let regs = Self::default();
        for &(r, v) in values {
            regs.values.borrow_mut().insert(r, v);
        }
        regs
    }
    fn set(&self, r: u64, v: u32) {
        self.values.borrow_mut().insert(r, v);
    }
    fn writes(&self) -> Vec<(u64, u32)> {
        self.writes.borrow().clone()
    }
}

impl MmioWindow for Regs {
    fn read32(&self, r: u64) -> u32 {
        self.reads.set(self.reads.get() + 1);
        *self.values.borrow().get(&r).unwrap_or(&0)
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        let old = *self.values.borrow().get(&r).unwrap_or(&0);
        let new = match r {
            0x101018 if self.sticky.get() => old,
            0x101018 => old & !v,
            0x941c | 0x38941c if self.self_clear.get() => 0,
            _ => v,
        };
        self.values.borrow_mut().insert(r, new);
    }
}

fn identity(device: u16) -> (narf_bus::BusDevice, narf_bus::bar::MmioRegion) {
    let addr = narf_bus::PcieAddr::new(0, 0, 2, 0);
    let d = narf_bus::BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        id: narf_bus::DeviceId {
            vendor: 0x8086,
            device,
            class: 0x030000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: narf_bus::BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let b = narf_bus::bar::MmioRegion {
        phys: narf_memory::PhysAddr::new(0x10000000),
        virt: 0,
        len: 16 << 20,
        kind: narf_bus::bar::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    (d, b)
}

/// The route's lit display: GMD_ID_DISPLAY 20.00 and TRANSCONF_A enabled
/// with its state bit; every other register reads zero.
fn lit() -> Regs {
    Regs::with(&[(0x510a0, 20 << 22), (0x70008, 0xc000_0000)])
}

/// Display MMIO (0x40000..0x90000, which includes the pipe DMC and the DMC
/// program window) and the Type-C/PICA block (0x160000..0x170000).
fn display_register(r: u64) -> bool {
    (0x40000..0x90000).contains(&r) || (0x160000..0x170000).contains(&r)
}

fn smoke_xe2lpd_gt_display_admission_reads_display_only_and_never_flrs() -> TestResult {
    let (device, bar) = identity(0x6420);

    // Admitted with no write at all: no GU_CNTL trigger, no display write.
    let m = lit();
    let receipt = Receipt::admit_display(device, bar, &m, || true).unwrap();
    assert!(m.writes().is_empty());
    assert!(receipt.display_preserving());
    assert!(receipt.matches(device, bar, &m));
    // Wrong function or BAR never matches.
    let mut wrong = device;
    wrong.addr = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0, 0, 3, 0));
    assert!(!receipt.matches(wrong, bar, &m));
    let mut short = bar;
    short.len /= 2;
    assert!(!receipt.matches(device, short, &m));
    // Every later PTE write's proof fails once an FLR is in flight or has
    // completed, the function turned VF or the display IP changed.
    for (reg, value) in [
        (0x101010, 0x8000_0000),
        (0x101018, 0x8000_0000),
        (0x1901f8, 1),
        (0x510a0, 14 << 22),
        (0x510a0, u32::MAX),
    ] {
        let old = m.read32(reg);
        m.set(reg, value);
        assert!(!receipt.matches(device, bar, &m), "{reg:#x}");
        m.set(reg, old);
        assert!(receipt.matches(device, bar, &m));
    }
    // The panel may later go dark (DPMS) without invalidating the GT arena.
    m.set(0x70008, 0);
    assert!(receipt.matches(device, bar, &m));
    assert!(m.writes().is_empty());

    // BIOS-disabled driver FLR (GU_CNTL_PROTECTED.DRIVERINT_FLR_DIS) does not
    // refuse this profile; the headless FLR refuses it before any write.
    let m = lit();
    m.set(0x10100c, 0x8000_0000);
    assert!(Receipt::admit_display(device, bar, &m, || true).is_ok());
    let mut flr = DriverFlr::new(device, bar, 0).unwrap();
    assert!(matches!(
        flr.poll(&m, 0, || true),
        Poll::Ready(Err(Error::Unsupported))
    ));
    assert!(m.writes().is_empty());

    // A stale DRIVERFLR_STATUS is acknowledged once (W1C), then admitted.
    let m = lit();
    m.set(0x101018, 0x8000_0000);
    let receipt = Receipt::admit_display(device, bar, &m, || true).unwrap();
    assert_eq!(m.writes(), [(0x101018, 0x8000_0000)]);
    assert!(receipt.matches(device, bar, &m));
    // A status that does not clear refuses after that single write.
    let m = lit();
    m.set(0x101018, 0x8000_0000);
    m.sticky.set(true);
    assert_eq!(
        Receipt::admit_display(device, bar, &m, || true).err(),
        Some(Error::State)
    );
    assert_eq!(m.writes(), [(0x101018, 0x8000_0000)]);

    // No current PCI authority: refused before any MMIO.
    let m = lit();
    assert_eq!(
        Receipt::admit_display(device, bar, &m, || false).err(),
        Some(Error::Unavailable)
    );
    assert_eq!(m.reads.get(), 0);

    // Read-only refusals, each without a single write.
    for (reg, value, error) in [
        (0x101010, 0x8000_0000, Error::Busy), // FLR in flight
        (0x1901f8, 1, Error::Unsupported),    // VF
        (0x510a0, 0, Error::Unsupported),     // no display
        (0x510a0, 14 << 22, Error::Unsupported),
        (0x510a0, 30 << 22, Error::Unsupported),
        (0x510a0, (14 << 22) | (1 << 14), Error::Unsupported),
        (0x51000, 1 << 30, Error::Unsupported), // Pipe A fused off
        (0x70008, 0x8000_0000, Error::State),   // Pipe A not running
        (0x70008, 0, Error::State),
        (0x70008, u32::MAX, Error::Unavailable),
        // Inherited display DMA producers outside the route's primary.
        (0x71008, 0x8000_0000, Error::Busy), // TRANSCONF_B
        (0x73008, 0x4000_0000, Error::Busy), // TRANSCONF_D state
        (0x70280, 0x8000_0000, Error::Busy), // PLANE_CTL_2_A
        (0x73580, 0x8000_0000, Error::Busy), // PLANE_CTL_5_D
        (0x70080, 0x27, Error::Busy),        // CUR_CTL_A
        (0x71080, 0x04, Error::Busy),        // CUR_CTL_B mode bit
        (0x70b08, 1, Error::Busy),           // DSB_CTRL(A, 0) busy
        (0x72c08, 0x8000_0000, Error::Busy), // DSB_CTRL(C, 1) enabled
        (0x73d08, 0x8000_0000, Error::Busy), // DSB_CTRL(D, 2) enabled
        (0x43288, 0x8000_0000, Error::Busy), // FBC C
        (0x432c8, 0x8000_0000, Error::Busy), // FBC D
        (0x5f078, 0x8000_0000, Error::Busy), // PIPEDMC_FQ_CTRL(A)
        (0x5fc78, 0x8000_0000, Error::Busy), // PIPEDMC_FQ_CTRL(D)
        (0x45250, 0x10, Error::Busy),        // PIPEDMC_ENABLE_MTL(B)
        (0x45250, 0x1000, Error::Busy),      // PIPEDMC_ENABLE_MTL(D)
    ] {
        let m = lit();
        m.set(reg, value);
        assert_eq!(
            Receipt::admit_display(device, bar, &m, || true).err(),
            Some(error),
            "{reg:#x}={value:#x}"
        );
        assert!(m.writes().is_empty(), "{reg:#x}");
    }
    // The route's own primary and Pipe A's DMC are the admitted fetchers.
    for (reg, value) in [(0x70180, 0x8000_0000), (0x45250, 1)] {
        let m = lit();
        m.set(reg, value);
        assert!(Receipt::admit_display(device, bar, &m, || true).is_ok());
        assert!(m.writes().is_empty());
    }

    // Only Lunar Lake takes this profile: Panther Lake, Meteor Lake and a
    // short BAR refuse before any MMIO.
    for id in [0xb080, 0x7d55] {
        let (other, bar) = identity(id);
        let m = lit();
        assert_eq!(
            Receipt::admit_display(other, bar, &m, || true).err(),
            Some(Error::Unsupported)
        );
        assert_eq!(m.reads.get(), 0);
    }
    let m = lit();
    assert_eq!(
        Receipt::admit_display(device, short, &m, || true).err(),
        Some(Error::Unsupported)
    );
    assert_eq!(m.reads.get(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_gt",
    smoke_xe2lpd_gt_display_admission_reads_display_only_and_never_flrs
);

fn smoke_xe2lpd_gt_hardware_init_resets_gt_only() -> TestResult {
    use crate::intel_gpu_gt_hw::HardwareInit;
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let m = lit();
    m.self_clear.set(true);
    m.set(0xd8c, (20 << 22) | (4 << 14)); // graphics 20.04
    m.set(0x380d8c, 20 << 22); // media 20.00
    let mut hw = HardwareInit::new(platform).unwrap();
    hw.begin(&m, 0).unwrap();
    // Primary GT forcewake ACK.
    m.set(0xd84, 1);
    assert!(hw.poll(&m, 1).is_pending()); // media wake requested
    m.set(0x380dfc, 1);
    assert!(hw.poll(&m, 2).is_pending()); // media GRDOM_GUC
    m.set(0x38c000, 1); // media GS_MIA_IN_RESET
    assert!(hw.poll(&m, 3).is_pending()); // media GRDOM_FULL
                                          // The media proof, then the primary GRDOM_GUC.
    assert!(hw.poll(&m, 4).is_pending());
    m.set(0xc000, 1); // primary GS_MIA_IN_RESET
    assert!(hw.poll(&m, 5).is_pending()); // primary GRDOM_FULL
    m.set(0xfd0, 1); // steering semaphore
    let Poll::Ready(Ok(policy)) = hw.poll(&m, 6) else {
        panic!("GT-only reset and cache policy")
    };
    assert_eq!(policy.ggtt_pat(), 2);
    assert!(policy.media.is_some());

    let writes = m.writes();
    let at = |reg: u64, value: u32| {
        writes
            .iter()
            .position(|w| *w == (reg, value))
            .unwrap_or_else(|| panic!("{reg:#x}={value:#x} not written"))
    };
    // xe_guc_reset (GRDOM_GUC) then do_gt_reset (GRDOM_FULL) on the media GT
    // and on the primary GT, all before the first PAT/MOCS write.
    let order = [
        at(0x38941c, 8),
        at(0x38941c, 1),
        at(0x941c, 8),
        at(0x941c, 1),
        at(0x4808, 0xf),
    ];
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
    // Xe2 PAT3 = XE2_PAT(0, 0, 0, 3, 3, 0): the uncached index display
    // scanout uses (xe_pat.c idx[XE_CACHE_NONE] = 3).
    assert!(writes.contains(&(0x480c, 0x3c)));
    // No driver FLR and no display register is written.
    assert!(!writes
        .iter()
        .any(|(r, _)| matches!(*r, 0x101010 | 0x101018)));
    assert!(!writes.iter().any(|(r, _)| display_register(*r)));
    // No GGTT entry (BAR0 + 8 MiB) is written by the reset.
    assert!(!writes.iter().any(|(r, _)| *r >= 0x80_0000));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_gt",
    smoke_xe2lpd_gt_hardware_init_resets_gt_only
);

fn smoke_xe2lpd_gt_profile_selection_keeps_headless_flr() -> TestResult {
    use crate::intel_gpu::Generation;
    use crate::intel_gpu_gt::Gen12Platform;
    let lnl = GtPlatform::Integrated(Generation::LunarLake);
    let ptl = GtPlatform::Integrated(Generation::PantherLake);
    // Without the route every Lunar Lake/Panther Lake function keeps the
    // headless profile; the route takes the display-preserving one only on
    // Lunar Lake with a lit mode.
    for mode in [false, true] {
        assert_eq!(lnl_profile(lnl, false, mode), Some(LnlProfile::Headless));
        assert_eq!(lnl_profile(ptl, false, mode), Some(LnlProfile::Headless));
        assert_eq!(lnl_profile(ptl, true, mode), None);
    }
    assert_eq!(
        lnl_profile(lnl, true, true),
        Some(LnlProfile::DisplayPreserving)
    );
    assert_eq!(lnl_profile(lnl, true, false), None);
    for other in [
        GtPlatform::Integrated(Generation::MeteorLake),
        GtPlatform::Gen12(Gen12Platform::TigerLake),
        GtPlatform::Alchemist,
        GtPlatform::Battlemage,
    ] {
        for (route, mode) in [(false, false), (true, true)] {
            assert_eq!(lnl_profile(other, route, mode), None);
        }
    }
    // System suspend: refused on the D0-only profiles.
    assert!(system_suspend_admitted(false, false));
    assert!(!system_suspend_admitted(true, false));
    assert!(!system_suspend_admitted(false, true));

    // The headless profile's cold start still requests the driver FLR, on
    // the same lit-display registers the display profile only reads: fresh
    // DRIVERFLR_STATUS clear, then the GU_CNTL trigger.
    let (device, bar) = identity(0x6420);
    let m = lit();
    let mut flr = DriverFlr::new(device, bar, 0).unwrap();
    assert!(flr.poll(&m, 0, || true).is_pending());
    assert_eq!(
        m.writes(),
        [(0x101018, 0x8000_0000), (0x101010, 0x8000_0000)]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_gt",
    smoke_xe2lpd_gt_profile_selection_keeps_headless_flr
);

/// A native Xe backend that reports only its LNL GT profile.
#[derive(Debug)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) struct ProfileBackend(pub(crate) bool);
impl crate::intel_gpu_user::UserBackend for ProfileBackend {
    fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        None
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn display_preserving(&self) -> bool {
        self.0
    }
    fn submit<'a>(
        &'a self,
        _: alloc::sync::Arc<crate::intel_gpu_user::UserContext>,
        _: crate::intel_gpu_user::UserBatch,
    ) -> narf_filesystem::FsFuture<'a, alloc::sync::Arc<crate::intel_gpu_fence::CompletionFence>>
    {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::NoDevice) })
    }
}

/// `DRM_IOCTL_XE_GEM_CREATE` of an 8 KiB system object with `flags` and
/// `cpu_caching` (1 WB, 2 WC); the new handle.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) fn xe_gem_create(
    info: &crate::intel_gpu_render::DeviceInfo,
    gem: &crate::intel_gpu_gem::GemState,
    flags: u32,
    caching: u8,
) -> Result<u32, narf_filesystem::FsError> {
    use crate::intel_gpu_uapi::{put32, put64, u32_at};
    let user = crate::intel_gpu_render::tests::User::new();
    let mut wire = [0u8; 56];
    put64(&mut wire, 8, 8192);
    put32(&mut wire, 16, 1);
    put32(&mut wire, 20, flags);
    wire[32] = caching;
    user.store(64, &wire);
    crate::intel_gpu_xe::XeFile::new()
        .dispatch(info, crate::intel_gpu_xe_uapi::GEM_CREATE, 64, &user, gem)
        .expect("native Xe ioctl")?;
    Ok(u32_at(&user.load(64, 56), 28))
}

/// `DRM_XE_GEM_CREATE_FLAG_SCANOUT` (2) on Lunar Lake follows the GT
/// profile: the display-20 route's display-preserving owner creates a WC
/// system object marked for scanout (xe_bo.c::xe_gem_create_ioctl sets
/// `XE_BO_FLAG_SCANOUT`; xe_ttm_tt_create keeps the iGPU WC caching) and,
/// as xe does, refuses SCANOUT with WB caching. The headless profile keeps
/// refusing the flag, and `NO_COMPRESSION` (8) stays refused on both.
#[cfg(target_arch = "x86_64")]
fn smoke_xe2lpd_gt_scanout_create_flag_follows_display_profile() -> TestResult {
    use crate::intel_gpu::Generation;
    use narf_filesystem::FsError;
    let info = |platform, display: Option<bool>| crate::intel_gpu_render::DeviceInfo {
        device_id: 0x6420,
        platform,
        memory_bytes: 0x8000_0000,
        hwconfig: None,
        topology: None,
        vram: None,
        backend: display.map(|display| {
            alloc::sync::Arc::new(ProfileBackend(display))
                as alloc::sync::Arc<dyn crate::intel_gpu_user::UserBackend>
        }),
    };
    let lnl = GtPlatform::Integrated(Generation::LunarLake);
    let gem = crate::intel_gpu_gem::GemState::new();

    let display = info(lnl, Some(true));
    let handle = xe_gem_create(&display, &gem, 2, 2).unwrap();
    let object = gem.object(handle).unwrap();
    assert!(object.scanout() && object.is_wc());
    // Without the flag the object is WC but not marked for scanout.
    let plain = gem
        .object(xe_gem_create(&display, &gem, 0, 2).unwrap())
        .unwrap();
    assert!(plain.is_wc() && !plain.scanout());
    // xe: SCANOUT with DRM_XE_GEM_CPU_CACHING_WB is EINVAL.
    assert_eq!(
        xe_gem_create(&display, &gem, 2, 1),
        Err(FsError::InvalidData)
    );
    assert_eq!(
        xe_gem_create(&display, &gem, 8, 2),
        Err(FsError::InvalidData)
    );
    // The headless profile (or no GT owner) has no scanout representation.
    for headless in [info(lnl, Some(false)), info(lnl, None)] {
        assert_eq!(
            xe_gem_create(&headless, &gem, 2, 2),
            Err(FsError::InvalidData)
        );
        assert!(xe_gem_create(&headless, &gem, 0, 2).is_ok());
    }
    // Panther Lake follows the same display-preserving profile gate.
    let ptl = GtPlatform::from_pci(0x8086, 0xb080).unwrap();
    assert!(ptl.is_ptl());
    let ptl_handle = xe_gem_create(&info(ptl, Some(true)), &gem, 2, 2).unwrap();
    assert!(gem.object(ptl_handle).unwrap().scanout());
    assert_eq!(
        xe_gem_create(&info(ptl, Some(false)), &gem, 2, 2),
        Err(FsError::InvalidData)
    );
    // Meteor Lake's display-14 iGPU admission is unchanged.
    let mtl = info(GtPlatform::Integrated(Generation::MeteorLake), None);
    let handle = xe_gem_create(&mtl, &gem, 2, 2).unwrap();
    assert!(gem.object(handle).unwrap().scanout());
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_gt",
    smoke_xe2lpd_gt_scanout_create_flag_follows_display_profile
);
