//! Per-card fixed-mode Intel KMS transactions. The async mutex is outermost:
//! no Card/CONTROLLER/IRQ spinlock may survive a hardware-latch await.
//! Display DMA owns front and pending GEM pages until independent retirement.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
};
use narf_filesystem::FsError;
use narf_lib::{
    mutex::{Mutex, MutexGuard},
    sync::IrqSafeSpinLock,
};

use crate::{
    drm::card::FlipStamp,
    intel_gpu::{ActiveScanout, Generation},
    intel_gpu_aux::MmioWindow,
    intel_gpu_gem::GemObject,
    intel_gpu_gtt::{
        check_ggtt_range, GEM_SCANOUT_GTT_END, GEM_SCANOUT_GTT_START, GGTT_ARRAY_BASE,
    },
    intel_gpu_pipes::Pipe,
    intel_gpu_scanout::{Geometry, Presenter, ScanoutError, SurfaceId},
    intel_gpu_scanout_io::{DisplayAccess, PollIo, SavedStatus},
};

type Wait<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

fn x_tiled_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
) -> Result<(), FsError> {
    tiled_profile(io, geometry, timing, crate::intel_gpu_scanout::Layout::X)
}
fn tiled_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
    layout: crate::intel_gpu_scanout::Layout,
) -> Result<(), FsError> {
    if !io.console_access_ok() {
        return Err(FsError::NoDevice);
    }
    if let Some(family) = io.gen12_family() {
        return gen12_primary::view_profile(io, geometry, timing, family, layout);
    }
    crate::intel_gpu_scanout::View {
        origin: Default::default(),
        layout,
        input: Default::default(),
    }
    .footprint(geometry)
    .map_err(scanout_error)?;
    crate::intel_gpu_display_resources::Profile::capture_timing(io, timing)?;
    let chicken = io.read32(0x7026c);
    if chicken == u32::MAX {
        return Err(FsError::NoDevice);
    }
    if chicken & (1 << 19) == 0 {
        return Err(FsError::Unsupported);
    }
    if !io.console_access_ok() {
        return Err(FsError::NoDevice);
    }
    Ok(())
}
pub(crate) fn tile4_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
) -> Result<(), FsError> {
    tiled_profile(
        io,
        geometry,
        timing,
        crate::intel_gpu_scanout::Layout::Tile4,
    )?;
    crate::intel_gpu_display_resources::Primary::capture(io, timing)?;
    Ok(())
}

/// Read-only fixed opaque cpp4 input qualification. Timing, WM/DDB/PM,
/// active route and output depth remain the pre-existing resource contract.
fn xr30_resource_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
) -> Result<(), FsError> {
    if !io.xr30_device()
        || io.gen12_family().is_some()
        || !io.internal_primary_claimed()
        || !io.console_access_ok()
        || !io.access_ok()
        || (u32::from(timing.width), u32::from(timing.height)) != (geometry.width, geometry.height)
    {
        return Err(FsError::Unsupported);
    }
    crate::intel_gpu_scanout::View::default()
        .footprint(geometry)
        .map_err(scanout_error)?;
    crate::intel_gpu_display_resources::Profile::capture_timing(io, timing)?;
    timing.check(io, None)?;
    if io.read32(0x70188) != geometry.pitch / 64
        || io.read32(0x70190) != ((geometry.height - 1) << 16) | (geometry.width - 1)
    {
        return Err(FsError::Unsupported);
    }
    // The existing fixed internal route remains A/SST/8bpc with its source
    // clock and normal transport pattern. This observes; it never retrains or
    // changes output BPC in response to the framebuffer's input precision.
    let route = io.read32(0x60400);
    let width = route & 7;
    let ddi = io.read32(0x64000);
    let buf = io.read32(0x64004);
    if !matches!(width, 0 | 2 | 6)
        || route & !7 != 0x8a000000
        || io.read32(0x46140) != 0x10000000
        || io.read32(0x60540) & 0x80040700 != 0x80040300
        || ddi == u32::MAX
        || ddi & (1 << 31) == 0
        || buf == u32::MAX
        || buf & 0x31000080 != 0x31000000
        || buf & 0xe != width
    {
        return Err(FsError::Unsupported);
    }
    if !io.console_access_ok() {
        return Err(FsError::NoDevice);
    }
    Ok(())
}

/// Normal admission requires this exact function's live, proved backend
/// incarnation in addition to resources. Reset recovery uses the explicitly
/// fresh resource-only contract while admission is still epoch zero.
fn xr30_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
) -> Result<u64, FsError> {
    let epoch = io
        .published_epoch()
        .filter(|e| *e != 0)
        .ok_or(FsError::NoDevice)?;
    xr30_resource_profile(io, geometry, timing)?;
    if io.published_epoch() != Some(epoch) {
        return Err(FsError::NoDevice);
    }
    Ok(epoch)
}

/// Initial install/console-replacement discovery shares the live fixed-profile
/// checks but additionally requires the original XR24 RGB bypass. Queries only
/// read the cached result; this read-only helper never acquires DMA or writes.
pub(crate) fn xr30_discovery_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
) -> bool {
    let Ok(epoch) = xr30_profile(io, geometry, timing) else {
        return false;
    };
    crate::intel_gpu_color::Owner::capture(io, Generation::MeteorLake).is_ok()
        && io.published_epoch() == Some(epoch)
}

/// The production implementation retains PCI authority and a permanent UC
/// BAR. Tests implement the same platform boundary with native register models.
pub(crate) trait Platform:
    DisplayAccess + Clone + core::fmt::Debug + Send + Sync + 'static
{
    fn published_epoch(&self) -> Option<u64> {
        None
    }
    fn xr30_device(&self) -> bool {
        false
    }
    fn gen12_family(&self) -> Option<crate::intel_gpu_gt::Gen12Platform> {
        None
    }
    fn internal_primary_claimed(&self) -> bool {
        true
    }
    fn takeover(&self, owned_cursor: bool) -> Result<(), FsError>;
    fn color_takeover(&self, owned_cursor: bool) -> Result<(), FsError> {
        self.takeover(owned_cursor)
    }
    fn color_restored(&self) {}
    fn console_published(&self, _console: &ActiveScanout) {}
    fn pause_console(&self) -> Wait<'_>;
    fn resume_console(&self);
    fn now(&self) -> u64;
    fn tick(&self) -> Wait<'_>;
    fn console_access_ok(&self) -> bool {
        self.access_ok()
    }
    fn reset_lost(&self) -> bool {
        false
    }
    /// A fresh, checked view used only after GT startup and outside its lock.
    fn recovery_platform(&self, owned_dsb: bool, owned_cursor: bool) -> Result<Self, FsError>;
    fn recovery_complete(&self);
    /// Display power for one KMS hardware conversation: DC5/DC6 are
    /// exited before `Ok` and stay off until the reference drops.
    /// Inert by default (no display-14 DC service).
    fn display_power(&self) -> Result<crate::intel_gpu_dc_states::DcRef, FsError> {
        Ok(crate::intel_gpu_dc_states::DcRef::none(
            crate::intel_gpu_dc_states::DcUser::Kms,
        ))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Physical {
    index: u32,
    bar: narf_bus::MmioRegion,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    window: crate::intel_gpu_gt_hw::AuthorizedWindow,
    generation: Generation,
    /// Shared by every retained PollIo clone. A GT reset invalidates all
    /// outstanding display/cache witnesses; reset alone never retires DMA.
    reset_lost: Arc<AtomicBool>,
    recovering: bool,
}
impl MmioWindow for Physical {
    fn read32(&self, offset: u64) -> u32 {
        if self.reset_lost() && !self.recovering {
            u32::MAX
        } else {
            self.window.read32(offset)
        }
    }
    fn write32(&self, offset: u64, value: u32) {
        if !self.reset_lost() || self.recovering {
            self.window.write32(offset, value);
        }
    }
}
// SAFETY: this window is used only under the per-card KMS mutex. Every
// modeset/power path must first quiesce and acquire its legacy guard. The
// function's iGPU runtime-PM owner forbids autosuspend with an active panel.
// AuthorizedWindow invokes the current capability for each MMIO access.
unsafe impl DisplayAccess for Physical {
    fn ggtt_key(&self) -> Option<u64> {
        Some(self.bar.phys.raw())
    }

    fn access_ok(&self) -> bool {
        self.console_access_ok()
            && (self.generation != Generation::MeteorLake || self.read32(0x4804) == 4)
    }
}
impl Physical {
    fn publish_console_formats(&self, console: &ActiveScanout, required_epoch: Option<u64>) {
        if required_epoch.is_some_and(|epoch| self.published_epoch() != Some(epoch)) {
            return;
        }
        let geometry = scanout_geometry(console);
        // No Card spinlock spans console PTE/resource validation. Qualification
        // grants CTM only; display12 and13 have different native LUT layouts.
        let family = self.gen12_family();
        let ctm_only = family.is_some_and(|family| {
            gen12_primary::Owner::capture(self, console, family, self.bar.len).is_ok()
                && crate::intel_gpu_color::Owner::capture_gen12(self, family).is_ok()
        });
        let timing = crate::drm_registry::mode_state(self.index).and_then(|card| {
            let card = card.lock();
            let mode = card.crtcs.first()?.mode?;
            if (mode.width, mode.height) != (geometry.width, geometry.height) {
                return None;
            }
            let wire = card.mode_wire(&mode);
            Some(crate::intel_gpu_dsb::Timing {
                clock: wire.clock,
                width: wire.hdisplay,
                height: wire.vdisplay,
                htotal: wire.htotal,
                vtotal: wire.vtotal,
                flags: wire.flags,
            })
        });
        let hw_cursor = ctm_only
            && family.zip(timing).is_some_and(|(family, timing)| {
                timing.valid()
                    && crate::intel_gpu_gen12_cursor_resources::Profile::capture(
                        self, timing, family,
                    )
                    .is_ok()
            });
        let gen12_views = hw_cursor
            && family.zip(timing).is_some_and(|(family, timing)| {
                gen12_primary::view_profile(
                    self,
                    geometry,
                    timing,
                    family,
                    crate::intel_gpu_scanout::Layout::Linear,
                )
                .is_ok()
            });
        let gen12_x = gen12_views
            && family.zip(timing).is_some_and(|(family, timing)| {
                gen12_primary::view_profile(
                    self,
                    geometry,
                    timing,
                    family,
                    crate::intel_gpu_scanout::Layout::X,
                )
                .is_ok()
            });
        let backend =
            crate::drm_registry::card(self.index).and_then(|card| card.intel_user_backend());
        let epoch = self.published_epoch();
        let xr30 = timing.is_some_and(|timing| xr30_discovery_profile(self, geometry, timing));
        if let Some(card) = crate::drm_registry::mode_state(self.index) {
            let mut card = card.lock();
            if required_epoch.is_some_and(|required| {
                epoch != Some(required)
                    || backend
                        .as_ref()
                        .and_then(|b| b.status())
                        .is_none_or(|current| current.epoch != required)
            }) {
                return;
            }
            card.intel_xr30 = xr30
                && epoch.is_some()
                && backend
                    .as_ref()
                    .and_then(|b| b.status())
                    .is_some_and(|current| {
                        Some(current.epoch) == epoch
                            && Some(current.platform)
                                == crate::intel_gpu_gt::GtPlatform::from_pci(
                                    self.device.id.vendor,
                                    self.device.id.device,
                                )
                    });
            if let Some(family) = family {
                card.intel_ctm_only = ctm_only;
                card.intel_hw_cursor = hw_cursor;
                // The same retained fixed route/resource/bypass and Gen12 DSB
                // proof qualifies only origin-zero linear joint commits.
                card.intel_gen12_joint = hw_cursor;
                card.intel_gen12_views = gen12_views.then_some(family);
                card.intel_gen12_lut =
                    hw_cursor.then(|| crate::intel_gpu_color::Profile::gen12(family));
                if let Some(crtc) = card.crtcs.first().map(|c| c.id) {
                    if ctm_only && card.crtc_color(crtc).is_none() {
                        card.crtc_color.push(crate::drm::card::CrtcColor::new(crtc));
                    } else if !ctm_only {
                        // A legacy console replacement has already restored color.
                        // Do not expose the generic vendor's LUTs for a stale row.
                        card.crtc_color.retain(|color| color.crtc != crtc);
                        card.collect_blobs();
                    }
                }
            }
            card.intel_x_tiled = gen12_x;
            card.intel_tile4 = false;
            if self.generation == Generation::MeteorLake {
                if let Some(mode) = card.crtcs.first().and_then(|c| c.mode) {
                    if (mode.width, mode.height) != (geometry.width, geometry.height) {
                        return;
                    }
                    let wire = card.mode_wire(&mode);
                    let timing = crate::intel_gpu_dsb::Timing {
                        clock: wire.clock,
                        width: wire.hdisplay,
                        height: wire.vdisplay,
                        htotal: wire.htotal,
                        vtotal: wire.vtotal,
                        flags: wire.flags,
                    };
                    card.intel_x_tiled = x_tiled_profile(self, geometry, timing).is_ok();
                    card.intel_tile4 = tile4_profile(self, geometry, timing).is_ok();
                }
            }
        }
    }
}
impl Platform for Physical {
    fn published_epoch(&self) -> Option<u64> {
        let backend = crate::drm_registry::card(self.index)?.intel_user_backend()?;
        let status = backend.status()?;
        (status.epoch != 0
            && Some(status.platform)
                == crate::intel_gpu_gt::GtPlatform::from_pci(
                    self.device.id.vendor,
                    self.device.id.device,
                )
            && status.engines.bits() != 0)
            .then_some(status.epoch)
    }
    fn xr30_device(&self) -> bool {
        self.generation == Generation::MeteorLake
            && self.device.id.vendor == 0x8086
            && matches!(
                self.device.id.device,
                0x7d40
                    | 0x7d45
                    | 0x7d55
                    | 0x7d60
                    | 0x7dd5
                    | 0x7d41
                    | 0x7d51
                    | 0x7d67
                    | 0x7dd1
                    | 0xb640
            )
    }
    fn gen12_family(&self) -> Option<crate::intel_gpu_gt::Gen12Platform> {
        match crate::intel_gpu_gt::GtPlatform::from_pci(
            self.device.id.vendor,
            self.device.id.device,
        ) {
            Some(crate::intel_gpu_gt::GtPlatform::Gen12(family)) => Some(family),
            _ => None,
        }
    }
    fn internal_primary_claimed(&self) -> bool {
        crate::intel_gpu_multipipe::pipe_owner(Pipe::A)
            == Some(crate::intel_gpu_multipipe::PipeOwner {
                ddi: crate::intel_gpu_ddi::Ddi::A,
                used_for: crate::intel_gpu_multipipe::PipeUse::InternalPanel,
            })
    }
    fn console_published(&self, console: &ActiveScanout) {
        self.publish_console_formats(console, None);
    }
    fn takeover(&self, owned_cursor: bool) -> Result<(), FsError> {
        // Only an execution-tested backend has retired inherited GT owners
        // and established the disjoint >=256-MiB kernel GGTT arena. Untrusted
        // commands cannot address this privileged 160..256-MiB display range.
        let backend = crate::drm_registry::card(self.index)
            .and_then(|card| card.intel_user_backend())
            .ok_or(FsError::Unsupported)?;
        if backend.status().is_none() {
            return Err(FsError::Busy);
        }
        if !self.access_ok() {
            return Err(FsError::NoDevice);
        }
        fetchers_with_cursor(self, self.generation, false, owned_cursor)?;
        if crate::intel_gpu::with_controller(|gpu| gpu.gtt_mmadr.phys) != Some(self.bar.phys) {
            return Err(FsError::NoDevice);
        }
        if self.gen12_family().is_some() && !self.internal_primary_claimed() {
            return Err(FsError::NoDevice);
        }
        // Keep the same current-capability/reset checks during PSR and AUX
        // waits as during PTE/plane access; no controller lock spans a wait.
        crate::intel_gpu_edp::kms_inhibit_psr(self).map_err(|_| crate::intel_gpu_user::io_error())
    }
    fn color_takeover(&self, owned_cursor: bool) -> Result<(), FsError> {
        if self.gen12_family().is_some() && !self.internal_primary_claimed() {
            return Err(FsError::NoDevice);
        }
        if !self.console_access_ok() {
            return Err(FsError::NoDevice);
        }
        fetchers_with_cursor(self, self.generation, false, owned_cursor)?;
        if crate::intel_gpu::with_controller(|gpu| gpu.gtt_mmadr.phys) != Some(self.bar.phys) {
            return Err(FsError::NoDevice);
        }
        crate::intel_gpu_edp::kms_inhibit_psr(self).map_err(|_| crate::intel_gpu_user::io_error())
    }
    fn color_restored(&self) {
        if let Some(card) = crate::drm_registry::mode_state(self.index) {
            let mut card = card.lock();
            card.intel_master_restored();
        }
    }
    fn pause_console(&self) -> Wait<'_> {
        Box::pin(crate::intel_gpu::kms_pause_console())
    }
    fn resume_console(&self) {
        if self.reset_lost() {
            return;
        }
        crate::intel_gpu_edp::kms_release_psr();
        crate::intel_gpu::kms_resume_console();
    }
    fn now(&self) -> u64 {
        narf_time::monotonic_ns()
    }
    fn tick(&self) -> Wait<'_> {
        Box::pin(narf_time::SleepUntil::new(
            narf_time::Deadline::after_us(250).as_instant(),
        ))
    }
    fn console_access_ok(&self) -> bool {
        if self.reset_lost() && !self.recovering {
            return false;
        }
        if narf_bus::pci::power_state(&self.cap, &self.device)
            != Ok(Some(narf_bus::pci::PciPowerState::D0))
        {
            return false;
        }
        let pipe = self.read32(0x70008);
        pipe != u32::MAX && pipe & 0xc0000000 == 0xc0000000
    }
    fn reset_lost(&self) -> bool {
        self.reset_lost.load(Ordering::Acquire)
    }
    fn recovery_platform(&self, owned_dsb: bool, owned_cursor: bool) -> Result<Self, FsError> {
        let mut fresh = self.clone();
        fresh.recovering = true;
        if !fresh.access_ok() {
            return Err(FsError::NoDevice);
        }
        fetchers_with_cursor(&fresh, fresh.generation, owned_dsb, owned_cursor)?;
        if crate::intel_gpu::with_controller(|gpu| gpu.gtt_mmadr.phys) != Some(fresh.bar.phys) {
            return Err(FsError::NoDevice);
        }
        crate::intel_gpu_edp::kms_inhibit_psr(&fresh)
            .map_err(|_| crate::intel_gpu_user::io_error())?;
        Ok(fresh)
    }
    fn recovery_complete(&self) {
        self.reset_lost.store(false, Ordering::Release);
    }
    fn display_power(&self) -> Result<crate::intel_gpu_dc_states::DcRef, FsError> {
        crate::intel_gpu_dc_states::acquire_for_bar(
            &self.bar,
            crate::intel_gpu_dc_states::DcUser::Kms,
        )
        .map_err(|_| crate::intel_gpu_user::io_error())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
fn inherited_fetchers_idle(mmio: &impl MmioWindow, generation: Generation) -> Result<(), FsError> {
    fetchers_idle(mmio, generation, false)
}
/// Recovery alone may observe Pipe-A DSB0/1 backed by a retained transport.
/// This grants observation, never retirement: the caller must independently
/// stop source0 then leaf1 before fresh console/color programming.
#[cfg(any(test, feature = "kernel-test"))]
fn fetchers_idle(
    mmio: &impl MmioWindow,
    generation: Generation,
    owned_dsb: bool,
) -> Result<(), FsError> {
    fetchers_with_cursor(mmio, generation, owned_dsb, false)
}
fn fetchers_with_cursor(
    mmio: &impl MmioWindow,
    generation: Generation,
    owned_dsb: bool,
    owned_cursor: bool,
) -> Result<(), FsError> {
    // MIT Linux intel_cursor_regs.h, intel_fbc.c and intel_display_device.c:
    // neither cursor DMA nor FBC compression tracking belongs to this owner.
    // Refuse them rather than treating a primary latch as their retirement.
    let fbc_count = if generation == Generation::MeteorLake {
        2
    } else {
        1
    };
    for fbc in 0..fbc_count {
        let ctl = mmio.read32(0x43208 + fbc * 0x40);
        if ctl == u32::MAX {
            return Err(FsError::NoDevice);
        }
        if ctl & (1 << 31) != 0 {
            return Err(FsError::Unsupported);
        }
    }
    // All admitted ADL-S/P/N source families have four sprites; TGL has
    // six. ADL-S is display12 with HAS_D12_PLANE_MINIMIZATION.
    let count = match generation {
        Generation::MeteorLake | Generation::AlderLake => 5,
        _ => 7,
    };
    for pipe in 0..4u64 {
        let cursor = mmio.read32(0x70080 + pipe * 0x1000);
        if cursor == u32::MAX {
            return Err(FsError::NoDevice);
        }
        if cursor & 0x27 != 0 && !(owned_cursor && pipe == 0) {
            return Err(FsError::Unsupported);
        }
        // MIT intel_dsb_regs.h: an inherited display state buffer can fetch
        // GGTT commands and rewrite PLANE_SURF after a primary latch.
        for dsb in 0..3u64 {
            let ctl = mmio.read32(0x70b08 + pipe * 0x1000 + dsb * 0x100);
            if ctl == u32::MAX {
                return Err(FsError::NoDevice);
            }
            if ctl & ((1 << 31) | 1) != 0 && !(owned_dsb && pipe == 0 && dsb < 2) {
                return Err(FsError::Unsupported);
            }
        }
        for plane in 1..=count {
            if pipe == 0 && plane == 1 {
                continue;
            }
            let ctl = mmio.read32(0x70080 + pipe * 0x1000 + plane * 0x100);
            if ctl == u32::MAX {
                return Err(FsError::NoDevice);
            }
            if ctl & (1 << 31) != 0 {
                return Err(FsError::Unsupported);
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Joint {
    staged: bool,
    completion: Option<crate::intel_gpu_scanout::Completion>,
    color_complete: bool,
    deadline: u64,
}
struct PrimaryTarget {
    object: Arc<GemObject>,
    geometry: Geometry,
    view: crate::intel_gpu_scanout::View,
}

#[derive(Debug)]
struct State<M: Platform> {
    console: ActiveScanout,
    presenter: Option<Presenter<PollIo<M>>>,
    current: Option<(Arc<GemObject>, SurfaceId)>,
    pending: Option<(Arc<GemObject>, SurfaceId)>,
    next_ticket: u64,
    paused: bool,
    blocked: bool,
    failed: bool,
    recovery_status: Option<SavedStatus>,
    color: Option<crate::intel_gpu_color::Owner>,
    color_owned: bool,
    xr30_timing: Option<crate::intel_gpu_dsb::Timing>,
    xr30_epoch: Option<u64>,
    color_unpublished: bool,
    // DMA completion alone cannot publish a cancelled mixed framebuffer.
    mixed_unpublished: bool,
    dsb: Option<crate::intel_gpu_dsb::Owner<M>>,
    dsb_update: Option<crate::intel_gpu_color::Update>,
    joint: Option<Joint>,
    cursor: Option<crate::intel_gpu_cursor::Owner<M>>,
    primary_resources: Option<crate::intel_gpu_display_resources::Primary>,
    gen12_primary: Option<gen12_primary::Owner>,
    gen12_cursor_profile: Option<crate::intel_gpu_gen12_cursor_resources::Profile>,
    /// Exclusive inactive display12 RAM stays within this Device even after
    /// visible bypass restoration. No inherited active LUT is ever adopted.
    gen12_lut_ram_owned: bool,
}

#[derive(Debug)]
pub(crate) struct Device<M: Platform> {
    platform: M,
    generation: Generation,
    bar_len: u64,
    state: Mutex<State<M>>,
    geometry: IrqSafeSpinLock<Geometry>,
}
pub(crate) type Display = Device<Physical>;

impl Display {
    /// Admission epoch is published by the GT owner after reset recovery;
    /// reading it never acquires the GT or display transaction mutex.
    pub(crate) fn epoch(&self) -> u64 {
        crate::drm_registry::card(self.platform.index)
            .and_then(|card| card.intel_user_backend())
            .and_then(|backend| backend.status())
            .map_or(0, |status| status.epoch)
    }
}

#[derive(Debug)]
pub(crate) struct Guard<'a, M: Platform> {
    device: &'a Device<M>,
    state: MutexGuard<'a, State<M>>,
    /// DC_off for the whole session; released after the mutex.
    _power: crate::intel_gpu_dc_states::DcRef,
}

#[derive(Debug)]
pub(crate) struct LegacyGuard<'a, M: Platform = Physical> {
    state: MutexGuard<'a, State<M>>,
    platform: &'a M,
    geometry: &'a IrqSafeSpinLock<Geometry>,
    _power: crate::intel_gpu_dc_states::DcRef,
}
impl<M: Platform> LegacyGuard<'_, M> {
    pub(crate) fn suspend(&mut self) {
        self.state.blocked = true;
    }
    pub(crate) fn console_replaced(&mut self, console: &ActiveScanout) {
        if self.platform.reset_lost() {
            self.state.blocked = true;
            self.state.failed = true;
            return;
        }
        self.state.console = console.clone();
        *self.geometry.lock() = scanout_geometry(console);
        self.platform.console_published(console);
        self.state.blocked = false;
    }
}

static DISPLAYS: IrqSafeSpinLock<Vec<Arc<Display>>> = IrqSafeSpinLock::new(Vec::new());

pub(crate) fn install(
    index: u32,
    generation: Generation,
    bar: narf_bus::MmioRegion,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    console: ActiveScanout,
) {
    if matches!(generation, Generation::LunarLake | Generation::PantherLake) {
        return;
    }
    let platform = Physical {
        index,
        bar,
        device,
        cap,
        window: crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap),
        generation,
        reset_lost: Arc::new(AtomicBool::new(false)),
        recovering: false,
    };
    let display = Arc::new(Device::new(platform, generation, bar.len, console.clone()));
    let mut displays = DISPLAYS.lock();
    if displays
        .iter()
        .any(|old| old.platform.index == index || old.platform.bar.phys == bar.phys)
    {
        return;
    }
    displays.push(display.clone());
    drop(displays);
    // Display-14 DC service: DC states exited and held off (Init) until
    // the card worker loads the DMC program. Inert for every other IP.
    crate::intel_gpu_dc_states::install(generation, bar, cap);
    if let Some(card) = crate::drm_registry::mode_state(index) {
        let mut card = card.lock();
        card.native_atomic = true;
        card.intel_display = true;
        if generation == Generation::MeteorLake {
            if let Some(crtc) = card.crtcs.first().map(|c| c.id) {
                card.intel_ctm = true;
                if card.crtc_color(crtc).is_none() {
                    card.crtc_color.push(crate::drm::card::CrtcColor::new(crtc));
                }
            }
        }
    }
    display.platform.console_published(&console);
}
pub(crate) fn display(index: u32) -> Option<Arc<Display>> {
    DISPLAYS
        .lock()
        .iter()
        .find(|d| d.platform.index == index)
        .cloned()
}
pub(crate) fn display_for_bar(bar: &narf_bus::MmioRegion) -> Option<Arc<Display>> {
    DISPLAYS
        .lock()
        .iter()
        .find(|d| d.platform.bar.phys == bar.phys)
        .cloned()
}
/// Called by the existing GT service only after successful epoch publication,
/// outside its state guard. Busy KMS is retried on a later service iteration;
/// no await, resource transfer or new worker is introduced.
pub(crate) fn refresh_formats_after_publication(bar: &narf_bus::MmioRegion, epoch: u64) -> bool {
    // Display-14 DMC acquisition/(re)load and Init/Suspend release run on
    // the same no-lock card-worker pass; idempotent across retries.
    crate::intel_gpu_dc_states::service_after_publication(bar);
    let Some(display) = display_for_bar(bar) else {
        return true;
    };
    if display.generation != Generation::MeteorLake
        || display.platform.published_epoch() != Some(epoch)
    {
        return true;
    }
    let Some(state) = display.state.try_lock() else {
        return false;
    };
    if state.failed
        || state.blocked
        || state.paused
        || display.platform.reset_lost()
        || state.presenter.is_some()
        || state.color.is_some()
        || state.cursor.as_ref().is_some_and(|c| c.active())
    {
        return false;
    }
    // Format qualification reads live pipe/plane state: not inside DC5/DC6.
    let Ok(power) = display.platform.display_power() else {
        return false;
    };
    display
        .platform
        .publish_console_formats(&state.console, Some(epoch));
    drop(power);
    true
}

pub(crate) fn available(index: u32) -> bool {
    display(index).is_some()
}
pub(crate) fn active(index: u32) -> bool {
    display(index).is_some_and(|d| {
        d.platform.reset_lost()
            || d.state.try_lock().is_none_or(|s| {
                s.presenter.is_some()
                    || s.color.is_some()
                    || s.cursor.as_ref().is_some_and(|cursor| cursor.active())
                    || s.color_unpublished
                    || s.paused
                    || s.failed
            })
    })
}

/// Called after publishing backend epoch zero and before an automatic GT
/// reset, while the GT reset mutex is held. Never await or wait for display
/// ownership here: a display transaction may itself await a GT fence.
/// A busy/owned display loses its witnesses; GEM pages and the paused console
/// remain quarantined until an independent fresh console latch. GT reset is no fetch-stop
/// proof, and this path must neither unpin a front nor restore status bits.
pub(crate) fn quarantine_for_gt_reset(bar: &narf_bus::MmioRegion) {
    if let Some(display) = display_for_bar(bar) {
        quarantine_reset_state(&display.state, &display.platform.reset_lost);
    }
}

fn quarantine_reset_state<M: Platform>(state: &Mutex<State<M>>, lost: &AtomicBool) {
    if let Some(mut state) = state.try_lock() {
        if lost.load(Ordering::Acquire)
            || state.presenter.is_some()
            || state.color.is_some()
            || state.cursor.as_ref().is_some_and(|cursor| cursor.active())
            || state.color_unpublished
            || state.mixed_unpublished
            || state.paused
            || state.failed
        {
            lost.store(true, Ordering::Release);
            state.blocked = true;
            state.failed = true;
        }
        // An idle display can remain reusable: epoch zero prevents its next
        // takeover until fresh GT startup has re-established cache policy.
    } else {
        // The in-flight owner may be between validation and its first arm.
        // Poison its retained IO without touching/freeing its state.
        lost.store(true, Ordering::Release);
    }
}
/// Retire an owned Meteor Lake external route and its hotplug sources
/// (`intel_gpu_xelpg_external::teardown_mtl_external`) for this BAR. The
/// window is captured under the controller lock and programmed outside it;
/// other generations return before any register access.
fn retire_mtl_external(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
    let Some((window, generation)) = crate::intel_gpu::with_controller(|gpu| {
        (gpu.gtt_mmadr.phys == bar.phys).then(|| (gpu.mode_window(), gpu.chip.generation))
    })
    .flatten() else {
        return Ok(());
    };
    if crate::intel_gpu_xelpg_external::teardown_mtl_external(&window, generation) {
        Ok(())
    } else {
        Err(FsError::Busy)
    }
}

pub(crate) async fn quiesce_for_legacy(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
    // Display-14 suspend: DC states exited and held off for the whole
    // preparation; the DMC program is disabled only once it succeeded.
    crate::intel_gpu_dc_states::suspend_begin_for_bar(bar).map_err(|_| FsError::Busy)?;
    let result = async {
        crate::intel_gpu::retire_external_sst(bar).await?;
        retire_mtl_external(bar)?;
        if let Some(display) = display_for_bar(bar) {
            display.quiesce().await?;
        }
        if let Err(error) = crate::intel_dpcd_bl::suspend_complete_for_bar(bar).await {
            // A failed system-PM prepare hook is not resumed by the coordinator.
            // Attempt a fully verified replay while the original video is live;
            // failed replay keeps the AUX owner parked with its intent retained.
            let _ = crate::intel_dpcd_bl::resume_for_bar(bar);
            return Err(error);
        }
        Ok(())
    }
    .await;
    crate::intel_gpu_dc_states::suspend_finish_for_bar(bar, result.is_ok());
    result
}

pub(crate) async fn recover_after_gt_reset(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
    crate::intel_gpu::retire_external_sst(bar).await?;
    retire_mtl_external(bar)?;
    if let Some(display) = display_for_bar(bar) {
        display.recover().await?;
    }
    Ok(())
}

fn scanout_geometry(console: &ActiveScanout) -> Geometry {
    Geometry {
        width: console.width,
        height: console.height,
        pitch: console.stride_bytes,
    }
}

impl<M: Platform> Device<M> {
    fn new(platform: M, generation: Generation, bar_len: u64, console: ActiveScanout) -> Self {
        Self {
            platform,
            generation,
            bar_len,
            geometry: IrqSafeSpinLock::new(scanout_geometry(&console)),
            state: Mutex::new(State {
                console,
                presenter: None,
                current: None,
                pending: None,
                next_ticket: 1,
                paused: false,
                blocked: false,
                failed: false,
                recovery_status: None,
                color: None,
                color_owned: false,
                xr30_timing: None,
                xr30_epoch: None,
                color_unpublished: false,
                mixed_unpublished: false,
                dsb: None,
                dsb_update: None,
                joint: None,
                cursor: None,
                primary_resources: None,
                gen12_primary: None,
                gen12_cursor_profile: None,
                gen12_lut_ram_owned: false,
            }),
        }
    }
    pub(crate) fn reset_lost(&self) -> bool {
        self.platform.reset_lost()
    }
    pub(crate) fn console_geometry(&self) -> Geometry {
        *self.geometry.lock()
    }

    /// Called by the GT worker only after its reset/startup probes, with its
    /// mutex released and backend epoch still zero. No GT fence is awaited.
    pub(crate) async fn recover(&self) -> Result<(), FsError> {
        let mut state = self.state.lock().await;
        if !self.platform.reset_lost() {
            return Ok(());
        }
        let _power = self.platform.display_power()?;
        state.blocked = true;
        state.failed = true;
        state.paused = true;
        self.platform.pause_console().await;
        if let Some(old) = &state.presenter {
            old.retained_io().poison();
        }
        let fresh = self.platform.recovery_platform(
            state.dsb.as_ref().is_some_and(|dsb| dsb.exposed()),
            state.cursor.as_ref().is_some_and(|cursor| cursor.exposed()),
        )?;
        if let Some(owner) = &state.gen12_primary {
            owner.check_owned(
                &fresh,
                state.dsb.as_ref().is_some_and(|d| d.exposed()),
                state.cursor.as_ref().is_some_and(|c| c.exposed()),
            )?;
            owner.check_console_mapping(&fresh, &state.console)?;
        }
        if let Some(dsb) = state.dsb.as_mut() {
            dsb.recover_view(fresh.clone(), self.platform.now());
            while dsb.armed() && !dsb.poll(self.platform.now())? {
                self.platform.tick().await;
            }
            // DSB DMA is independent of GT and primary fetch. Stop/disable
            // chain source0 then leaf1 before any fresh console/color arm.
            dsb.shutdown()?;
            // Recovery authority is temporary. The retained same-VA owner
            // must observe the shared poison on every subsequent GT reset.
            // This only replaces IO; no access uses the still-lost view.
            dsb.recover_view(self.platform.clone(), self.platform.now());
        }
        state.dsb_update = None;
        // DSB0/1 are independently retired before changing any shadow WM.
        // A partial prior update cannot be adopted as a new resource baseline.
        let restored_resources = if let Some(resources) = state.primary_resources.as_mut() {
            Some(resources.restore(&fresh)?)
        } else {
            None
        };
        if state.cursor.as_ref().is_some_and(|cursor| cursor.active()) {
            let gen12_profile = state.gen12_cursor_profile;
            if let Some(profile) = gen12_profile {
                profile.check(&fresh, fresh.gen12_family().ok_or(FsError::NoDevice)?)?;
            }
            let cursor = state.cursor.as_mut().expect("cursor");
            cursor.replace_io(fresh.clone());
            cursor.begin_recovery_stop();
            let timing = cursor.timing;
            let regs = if let Some(profile) = gen12_profile {
                cursor.stage_with(
                    |enabled| profile.cursor_registers(enabled),
                    None,
                    true,
                    None,
                )?
            } else {
                let profile = match restored_resources {
                    Some(profile) => profile,
                    None => {
                        crate::intel_gpu_display_resources::Profile::capture_timing(&fresh, timing)?
                    }
                };
                cursor.stage(profile, None, true, None)?
            };
            {
                let dsb = state.dsb.as_mut().ok_or(FsError::NoDevice)?;
                dsb.recover_view(fresh.clone(), self.platform.now());
                dsb.arm(timing, &regs, None, self.platform.now())?;
                while !dsb.poll(self.platform.now())? {
                    self.platform.tick().await;
                }
            }
            state.cursor.as_mut().expect("cursor").complete()?;
            if let Some(profile) = gen12_profile {
                profile.check_cursor(&fresh, false)?;
            }
            // This stream belongs to the cursor, not dsb_update. Retire the
            // transport/status ownership before console/color work can reuse
            // it; terminal polling alone deliberately keeps armed=true.
            state.dsb.as_mut().expect("DSB").shutdown()?;
            state
                .cursor
                .as_mut()
                .expect("cursor")
                .replace_io(self.platform.clone());
            state
                .dsb
                .as_mut()
                .expect("DSB")
                .recover_view(self.platform.clone(), self.platform.now());
        }

        let saved = match state.recovery_status {
            Some(saved) => saved,
            None => {
                let saved = if let Some(old) = &state.presenter {
                    old.retained_io().saved_status()
                } else {
                    PollIo::snapshot_status(&fresh, self.generation)
                        .map_err(|_| FsError::NoDevice)?
                };
                state.recovery_status = Some(saved);
                saved
            }
        };
        // SAFETY: the old owner remains retained and poisoned. The GT worker
        // owns D0 and verified PAT policy; this mutex excludes every display
        // transition. Only the fresh view can observe/arm hardware now.
        let mut io = unsafe {
            PollIo::after_reset(fresh.clone(), self.generation, Pipe::A, self.bar_len, saved)
        }
        .map_err(|_| crate::intel_gpu_user::io_error())?;
        let family = fresh.gen12_family();
        let control = state.presenter.as_ref().map_or_else(
            || {
                family.map_or_else(
                    || fresh.read32(0x70180),
                    crate::intel_gpu_pipes::gen12_xrgb_control,
                )
            },
            |old| old.console_control(),
        );
        io.qualify_console(family, control, state.console.stride_bytes / 64)
            .map_err(|_| crate::intel_gpu_user::io_error())?;
        if let Some(old) = state.presenter.as_ref().filter(|p| p.tracks_xr30()) {
            let timing = state.xr30_timing.ok_or(FsError::NoDevice)?;
            xr30_resource_profile(&fresh, scanout_geometry(&state.console), timing)?;
            io.qualify_xr30().map_err(|_| FsError::NoDevice)?;
            let (original, current, pending) = old.retained_primary_controls();
            if !crate::intel_gpu_scanout::ScanoutIo::retain_primary_controls(
                &io, original, current, pending,
            ) {
                return Err(FsError::NoDevice);
            }
        }
        let format = io.format();
        let pat = if self.generation == Generation::MeteorLake {
            1
        } else {
            0
        };
        // SAFETY: all old current/pending owners remain in state.presenter;
        // retained console pages are outside their arena. No pre-reset
        // completion is consumed by this independent fresh transaction.
        let mut console = unsafe {
            Presenter::recover_console(
                io,
                self.bar_len,
                Pipe::A,
                format,
                pat,
                (
                    state.console.gtt_offset,
                    scanout_geometry(&state.console),
                    state
                        .presenter
                        .as_ref()
                        .map_or_else(|| fresh.read32(0x70180), |old| old.console_control()),
                    self.platform.now(),
                ),
            )
        }
        .map_err(scanout_error)?;
        loop {
            match console.poll(self.platform.now()).map_err(scanout_error)? {
                Some(_) => break,
                None => self.platform.tick().await,
            }
        }
        if let Some(resources) = state.primary_resources.as_mut() {
            resources.complete(&fresh)?;
        }
        if let Some(color) = state.color.as_mut() {
            color.recover_original(&fresh, self.platform.now())?;
            loop {
                if color.poll(&fresh, self.platform.now())?.is_some() {
                    break;
                }
                self.platform.tick().await;
            }
        }
        state.color = None;
        state.color_owned = false;
        state.color_unpublished = false;
        self.platform.color_restored();
        if let Some(old) = state.presenter.as_mut() {
            // SAFETY: the fresh console flip-done, SURFLIVE and changed
            // stable frame independently retired every old GEM fetch. Clear
            // with fresh IO; never re-enable the old poisoned adapter.
            unsafe { old.shutdown_retired_with(console.retained_io()) }.map_err(scanout_error)?;
        } else {
            console.shutdown_restored_console().map_err(scanout_error)?;
        }
        state.presenter = None;
        state.xr30_timing = None;
        state.xr30_epoch = None;
        state.primary_resources = None;
        state.gen12_primary = None;
        state.gen12_cursor_profile = None;
        state.current = None;
        state.pending = None;
        state.joint = None;
        state.recovery_status = None;
        // All old IO and mappings are closed before making normal accesses
        // valid again; only this new console witness reopens admission.
        drop(console);
        state.mixed_unpublished = false;
        self.platform.recovery_complete();
        self.platform.console_published(&state.console);
        state.failed = false;
        state.blocked = false;
        self.platform.resume_console();
        state.paused = false;
        Ok(())
    }
    pub(crate) async fn session(&self) -> Result<Guard<'_, M>, FsError> {
        let state = self.state.lock().await;
        if state.blocked || state.failed || self.platform.reset_lost() {
            return Err(FsError::NoDevice);
        }
        let _power = self.platform.display_power()?;
        Ok(Guard {
            device: self,
            state,
            _power,
        })
    }
    pub(crate) async fn quiesce(&self) -> Result<(), FsError> {
        let state = self.state.lock().await;
        let _power = self.platform.display_power()?;
        let mut guard = Guard {
            device: self,
            state,
            _power,
        };
        guard.restore_console().await?;
        self.platform.color_restored();
        guard.state.blocked = true;
        Ok(())
    }
}
impl<M: Platform> Device<M> {
    /// Stop-only external owner keeps all existing presenters/color/DMA in
    /// place. It cannot arm or adopt them; fresh authority is checked by its IO.
    pub(crate) fn legacy_drain(&self) -> Result<LegacyGuard<'_, M>, FsError> {
        let mut state = self.state.try_lock().ok_or(FsError::Busy)?;
        let _power = self.platform.display_power()?;
        state.blocked = true;
        Ok(LegacyGuard {
            state,
            platform: &self.platform,
            geometry: &self.geometry,
            _power,
        })
    }
    pub(crate) fn legacy(&self) -> Result<LegacyGuard<'_, M>, FsError> {
        let state = self.state.try_lock().ok_or(FsError::Busy)?;
        let _power = self.platform.display_power()?;
        if self.platform.reset_lost()
            || state.presenter.is_some()
            || state.color.is_some()
            || state.cursor.as_ref().is_some_and(|cursor| cursor.active())
            || state.color_unpublished
            || state.mixed_unpublished
            || state.paused
            || state.failed
            || (state.gen12_lut_ram_owned
                && (self.platform.read32(crate::intel_gpu_color::GAMMA) & (3 << 30) != 0
                    || self.platform.read32(crate::intel_gpu_color::MODE) != 0))
        {
            return Err(FsError::Busy);
        }
        Ok(LegacyGuard {
            state,
            platform: &self.platform,
            geometry: &self.geometry,
            _power,
        })
    }
}

fn scanout_error(error: ScanoutError) -> FsError {
    match error {
        ScanoutError::Unsupported | ScanoutError::Bounds => FsError::Unsupported,
        ScanoutError::Busy => FsError::Busy,
        _ => crate::intel_gpu_user::io_error(),
    }
}
impl<M: Platform> Guard<'_, M> {
    /// Dropping an owner future while console pause is pending leaves only a
    /// retained *intent*, not an exposed XR30 image. Reconcile on a later call,
    /// never in Drop: every current/pending/partial transport obligation and
    /// failed/reset/epoch-lost proof keeps the lease. This frees no resource.
    fn reconcile_unexposed_xr30(&mut self) {
        let Some(epoch) = self.state.xr30_epoch else {
            return;
        };
        if self.state.failed
            || self.device.platform.reset_lost()
            || self.device.platform.published_epoch() != Some(epoch)
            || self.state.pending.is_some()
            || self.state.joint.is_some()
            || self.state.dsb.as_ref().is_some_and(|d| d.armed())
            || self.state.color.as_ref().is_some_and(|c| c.pending())
            || self
                .state
                .presenter
                .as_ref()
                .is_some_and(|p| p.tracks_xr30())
        {
            return;
        }
        let original_input = if let Some(presenter) = &self.state.presenter {
            presenter.check_current(self.console_geometry()).is_ok()
        } else {
            let platform = &self.device.platform;
            let control = platform.read32(0x70180);
            control & !((1 << 14) | (1 << 13)) == 0x84000000
                && platform.read32(0x7019c) == self.state.console.gtt_offset
                && platform.read32(0x701ac) == self.state.console.gtt_offset
                && platform.read32(0x701a4) == 0
                && self.state.xr30_timing.is_some_and(|t| {
                    xr30_resource_profile(platform, self.console_geometry(), t).is_ok()
                })
                && self.state.color.as_ref().map_or_else(
                    || {
                        crate::intel_gpu_color::Owner::capture(platform, Generation::MeteorLake)
                            .is_ok()
                    },
                    |c| c.original_input_visible(platform),
                )
        };
        if original_input && self.device.platform.published_epoch() == Some(epoch) {
            self.state.xr30_timing = None;
            self.state.xr30_epoch = None;
        }
    }

    /// Recheck before publishing a hardware transaction. The synchronous GT
    /// loss path can poison a busy session without acquiring this mutex.
    pub(crate) fn ownership_valid(&self) -> Result<(), FsError> {
        if self.state.failed
            || self.state.blocked
            || self.device.platform.reset_lost()
            || !self.device.platform.console_access_ok()
        {
            return Err(FsError::NoDevice);
        }
        if let Some(timing) = self.state.xr30_timing {
            if Some(xr30_profile(
                &self.device.platform,
                self.console_geometry(),
                timing,
            )?) != self.state.xr30_epoch
            {
                return Err(FsError::NoDevice);
            }
        }
        if let Some(resources) = &self.state.primary_resources {
            resources.check_current(&self.device.platform)?;
        }
        if let Some(owner) = &self.state.gen12_primary {
            owner.check_owned(
                &self.device.platform,
                self.state.dsb.as_ref().is_some_and(|d| d.exposed()),
                self.state.cursor.as_ref().is_some_and(|c| c.exposed()),
            )?;
        }
        if let Some(profile) = self.state.gen12_cursor_profile {
            profile.check(
                &self.device.platform,
                self.device
                    .platform
                    .gen12_family()
                    .ok_or(FsError::NoDevice)?,
            )?;
            if let Some(cursor) = &self.state.cursor {
                if !cursor.pending() {
                    profile.check_cursor(&self.device.platform, cursor.resource_enabled())?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn console_geometry(&self) -> Geometry {
        Geometry {
            width: self.state.console.width,
            height: self.state.console.height,
            pitch: self.state.console.stride_bytes,
        }
    }
    pub(crate) fn console_fb(&self) -> narf_graphics_driver::generic::GenericFb {
        let console = &self.state.console;
        narf_graphics_driver::generic::GenericFb::new(
            console.phys_base,
            console.width,
            console.height,
            console.stride_bytes,
            32,
        )
    }
    pub(crate) fn check(&self, geometry: Geometry) -> Result<(), FsError> {
        if self.state.failed || self.state.blocked || self.device.platform.reset_lost() {
            return Err(FsError::NoDevice);
        }
        if geometry != self.console_geometry() {
            return Err(FsError::Unsupported);
        }
        if !self.device.platform.console_access_ok() {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
    fn ticket(&mut self) -> Result<u64, FsError> {
        let ticket = self.state.next_ticket;
        self.state.next_ticket = ticket.checked_add(1).ok_or(FsError::Busy)?;
        Ok(ticket)
    }
    async fn finish_pending(&mut self) -> Result<Option<FlipStamp>, FsError> {
        if self.state.joint.is_some() {
            return Err(FsError::Busy);
        }
        loop {
            let state = &mut *self.state;
            let Some(presenter) = state.presenter.as_mut() else {
                return Ok(None);
            };
            if !presenter.pending() {
                return Ok(None);
            }
            match presenter.poll(self.device.platform.now()) {
                Ok(Some(completion)) => {
                    if self.device.platform.reset_lost() {
                        state.failed = true;
                        return Err(FsError::NoDevice);
                    }
                    if let Some(resources) = state.primary_resources.as_mut() {
                        let result = if resources.pending() {
                            resources.complete(&self.device.platform)
                        } else {
                            resources.check_current(&self.device.platform)
                        };
                        result.inspect_err(|_| state.failed = true)?;
                    }
                    if let Some(owner) = &state.gen12_primary {
                        owner
                            .check_owned(
                                &self.device.platform,
                                state.dsb.as_ref().is_some_and(|d| d.exposed()),
                                state.cursor.as_ref().is_some_and(|c| c.exposed()),
                            )
                            .inspect_err(|_| state.failed = true)?;
                    }
                    if let Some(owner) = state.gen12_primary.as_mut() {
                        owner
                            .complete_view(&self.device.platform)
                            .inspect_err(|_| state.failed = true)?;
                    }
                    if let Some(retired) = completion.retired {
                        if let Err(error) = presenter.release(retired) {
                            state.failed = true;
                            return Err(scanout_error(error));
                        }
                    }
                    state.current = state.pending.take();
                    return Ok(Some(completion.stamp));
                }
                Ok(None) => self.device.platform.tick().await,
                Err(error) => {
                    state.failed = true;
                    return Err(scanout_error(error));
                }
            }
        }
    }
    /// Retain the unchanged fetch/timing/bandwidth witness for both primary
    /// and CTM-only sessions. Color never requires a GEM Presenter to exist.
    fn acquire_gen12_resources(&mut self) -> Result<(), FsError> {
        if !matches!(
            self.device.generation,
            Generation::TigerLake | Generation::AlderLake
        ) {
            return Ok(());
        }
        if let Some(owner) = &self.state.gen12_primary {
            return owner.check_owned(
                &self.device.platform,
                self.state.dsb.as_ref().is_some_and(|d| d.exposed()),
                self.state.cursor.as_ref().is_some_and(|c| c.exposed()),
            );
        }
        let family = self
            .device
            .platform
            .gen12_family()
            .ok_or(FsError::Unsupported)?;
        if (self.device.generation == Generation::TigerLake)
            != (family == crate::intel_gpu_gt::Gen12Platform::TigerLake)
        {
            self.state.failed = true;
            return Err(FsError::NoDevice);
        }
        let owner = gen12_primary::Owner::capture(
            &self.device.platform,
            &self.state.console,
            family,
            self.device.bar_len,
        )
        .inspect_err(|_| self.state.failed = true)?;
        self.state.gen12_primary = Some(owner);
        Ok(())
    }
    async fn start(&mut self) -> Result<(), FsError> {
        if let Some(presenter) = &self.state.presenter {
            if let Some(timing) = self.state.xr30_timing {
                xr30_profile(&self.device.platform, self.console_geometry(), timing)?;
                presenter
                    .retained_io()
                    .qualify_xr30()
                    .map_err(|_| FsError::NoDevice)?;
            }
            return Ok(());
        }
        check_ggtt_range(
            self.device.bar_len,
            GEM_SCANOUT_GTT_START,
            GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START,
        )
        .map_err(|_| FsError::Unsupported)?;
        // Publish cancellation-safe ownership before the first await.
        self.state.paused = true;
        self.device.platform.pause_console().await;
        if let Err(error) = self.device.platform.takeover(self.state.cursor.is_some()) {
            if self.device.platform.reset_lost() {
                self.state.failed = true;
            } else if !self
                .state
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.active())
            {
                self.device.platform.resume_console();
                self.state.paused = false;
            }
            return Err(error);
        }
        self.acquire_gen12_resources()?;
        let platform = &self.device.platform;
        // The startup proof retired inherited engines, all other universal
        // planes are disabled, and this arena is disjoint from every kernel
        // engine/console reservation. Claim it before exposing any GEM page.
        for offset in (GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).step_by(4096) {
            let pte = GGTT_ARRAY_BASE + offset / 4096 * 8;
            platform.write32(pte, 0);
            platform.write32(pte + 4, 0);
            if platform.read32(pte) != 0 || platform.read32(pte + 4) != 0 {
                self.state.failed = true;
                return Err(crate::intel_gpu_user::io_error());
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.state.recovery_status = Some(
            PollIo::snapshot_status(platform, self.device.generation).map_err(|_| {
                self.state.failed = true;
                crate::intel_gpu_user::io_error()
            })?,
        );
        // SAFETY: the per-card mutex owns the running internal plane and all
        // reserved PTEs. CPU epochs retired above; power/modeset/PSR cannot
        // transition before quiesce obtains this same mutex.
        let mut io = unsafe {
            PollIo::new(
                platform.clone(),
                self.device.generation,
                Pipe::A,
                self.device.bar_len,
            )
        }
        .map_err(|_| {
            self.state.failed = true;
            crate::intel_gpu_user::io_error()
        })?;
        let family = self.device.platform.gen12_family();
        let control = family.map_or_else(
            || platform.read32(0x70180),
            crate::intel_gpu_pipes::gen12_xrgb_control,
        );
        io.qualify_console(family, control, self.state.console.stride_bytes / 64)
            .map_err(|_| crate::intel_gpu_user::io_error())?;
        if let Some(timing) = self.state.xr30_timing {
            xr30_profile(platform, self.console_geometry(), timing)?;
            io.qualify_xr30().map_err(|_| FsError::NoDevice)?;
        }
        let format = io.format();
        let pat = if self.device.generation == Generation::MeteorLake {
            1
        } else {
            0
        };
        // SAFETY: startup owns the empty display-only arena and the original
        // console allocation remains retained by the registered IntelGpu.
        let mut presenter = unsafe {
            Presenter::new(
                io,
                self.device.bar_len,
                Pipe::A,
                format,
                pat,
                self.state.console.gtt_offset,
            )
        }
        .map_err(|error| {
            self.state.failed = true;
            scanout_error(error)
        })?;
        if let Some(family) = self.device.platform.gen12_family() {
            presenter.qualify_gen12(family).map_err(scanout_error)?;
        }
        self.state.presenter = Some(presenter);
        Ok(())
    }
    fn prepare_surface(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
        view: crate::intel_gpu_scanout::View,
    ) -> Result<SurfaceId, FsError> {
        if let Some((current, id)) = &self.state.current {
            if Arc::ptr_eq(current, &object)
                && self
                    .state
                    .presenter
                    .as_ref()
                    .expect("presenter")
                    .matches_view(*id, geometry, view)
            {
                return Ok(*id);
            }
        }
        self.state
            .presenter
            .as_mut()
            .expect("presenter")
            .prepare_layout(object, geometry, view)
            .map_err(scanout_error)
    }
    fn rollback_joint_before_arm(&mut self) -> Result<(), FsError> {
        if let Some(joint) = &self.state.joint {
            if joint.staged {
                // SAFETY: invoked only for the DSB's strict Unsupported
                // preflight before any command stream was armed/exposed.
                unsafe {
                    self.state
                        .presenter
                        .as_mut()
                        .expect("presenter")
                        .cancel_staged_dsb()
                }
                .map_err(scanout_error)
                .inspect_err(|_| self.state.failed = true)?;
            }
            if let Some(owner) = self.state.gen12_primary.as_mut() {
                owner
                    .rollback_view(&self.device.platform)
                    .inspect_err(|_| self.state.failed = true)?;
            }
            self.state.joint = None;
            let (_, id) = self.state.pending.take().expect("joint GEM owner");
            if self
                .state
                .current
                .as_ref()
                .is_none_or(|(_, front)| *front != id)
            {
                self.state
                    .presenter
                    .as_mut()
                    .expect("presenter")
                    .release(id)
                    .map_err(scanout_error)
                    .inspect_err(|_| self.state.failed = true)?;
            }
        }
        Ok(())
    }
    pub(crate) async fn present(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
    ) -> Result<FlipStamp, FsError> {
        self.reconcile_unexposed_xr30();
        self.check(geometry)?;
        if self.state.color_unpublished || self.state.mixed_unpublished {
            return Err(FsError::Busy);
        }
        if !object.is_wc() || !object.scanout() || object.is_vram() || object.is_userptr() {
            return Err(FsError::Unsupported);
        }
        self.finish_color().await?;
        self.finish_pending().await?;
        self.start().await?;
        let id = self.prepare_surface(object.clone(), geometry, Default::default())?;
        let ticket = self.ticket()?;
        // Record the new owner before arming. Cancellation never unpins it.
        self.state.pending = Some((object, id));
        if let Err(error) = self.state.presenter.as_mut().expect("presenter").arm(
            id,
            ticket,
            self.device.platform.now(),
        ) {
            if matches!(error, ScanoutError::Busy | ScanoutError::Unsupported) {
                self.state.pending = None;
                if self
                    .state
                    .current
                    .as_ref()
                    .is_none_or(|(_, current)| *current != id)
                {
                    self.state
                        .presenter
                        .as_mut()
                        .expect("presenter")
                        .release(id)
                        .map_err(scanout_error)?;
                }
                return Err(scanout_error(error));
            }
            self.state.failed = true;
            return Err(scanout_error(error));
        }
        self.finish_pending()
            .await?
            .ok_or_else(crate::intel_gpu_user::io_error)
    }
    pub(crate) async fn restore_console(&mut self) -> Result<(), FsError> {
        self.finish_cursor().await?;
        if self
            .state
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.active())
        {
            let timing = self.state.cursor.as_ref().expect("cursor").timing;
            self.cursor_inner(None, true, None, timing, true).await?;
        }
        self.restore_color().await?;
        self.restore_surface_inner().await?;
        self.state.mixed_unpublished = false;
        Ok(())
    }
    pub(crate) async fn restore_surface(&mut self) -> Result<(), FsError> {
        if self.state.mixed_unpublished {
            return Err(FsError::Busy);
        }
        self.restore_surface_inner().await
    }
    async fn restore_surface_inner(&mut self) -> Result<(), FsError> {
        self.reconcile_unexposed_xr30();
        self.finish_color().await?;
        if self.state.color_unpublished {
            return Err(FsError::Busy);
        }
        if !self.state.color_owned
            && !self
                .state
                .presenter
                .as_ref()
                .is_some_and(|p| p.tracks_xr30())
        {
            self.state.color = None;
        }
        if self.device.platform.reset_lost() {
            self.state.failed = true;
            return Err(FsError::NoDevice);
        }
        if self.state.failed {
            return Err(crate::intel_gpu_user::io_error());
        }
        self.finish_pending().await?;
        if self.state.presenter.is_some() {
            if !self
                .state
                .presenter
                .as_ref()
                .expect("presenter")
                .console_active()
            {
                if let Some(owner) = &self.state.gen12_primary {
                    let checked = owner
                        .check_owned(
                            &self.device.platform,
                            self.state.dsb.as_ref().is_some_and(|d| d.exposed()),
                            self.state.cursor.as_ref().is_some_and(|c| c.exposed()),
                        )
                        .and_then(|()| {
                            owner.check_console_mapping(&self.device.platform, &self.state.console)
                        });
                    checked.inspect_err(|_| self.state.failed = true)?;
                }
                if let Some(resources) = self.state.primary_resources.as_mut() {
                    resources
                        .restore(&self.device.platform)
                        .inspect_err(|_| self.state.failed = true)?;
                }
                let ticket = self.ticket()?;
                if let Some(owner) = self.state.gen12_primary.as_mut() {
                    owner.stage_view(&self.device.platform, Default::default())?;
                }
                self.state
                    .presenter
                    .as_mut()
                    .expect("presenter")
                    .arm_console(ticket, self.device.platform.now())
                    .map_err(scanout_error)
                    .inspect_err(|_| self.state.failed = true)?;
                self.state.pending = None;
                self.finish_pending().await?;
            }
            if self.state.xr30_timing.is_some() {
                let restored = if let Some(color) = self.state.color.as_mut() {
                    color
                        .console_restored(&self.device.platform)
                        .map(|()| color.original_visible())
                } else {
                    Ok(false)
                };
                let original = restored.inspect_err(|_| self.state.failed = true)?;
                if original {
                    self.state.color = None;
                    self.state.color_owned = false;
                }
            }
            self.state
                .presenter
                .as_mut()
                .expect("presenter")
                .shutdown_restored_console()
                .map_err(scanout_error)?;
            self.state.presenter = None;
            self.state.xr30_timing = None;
            self.state.xr30_epoch = None;
            self.state.primary_resources = None;
            if !self.state.color_owned && !self.state.cursor.as_ref().is_some_and(|c| c.active()) {
                self.state.gen12_primary = None;
            }
            self.state.current = None;
            self.state.recovery_status = None;
        }
        if self.state.paused
            && self.state.color.is_none()
            && !self
                .state
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.active())
        {
            self.device.platform.resume_console();
            self.state.paused = false;
        }
        Ok(())
    }
    async fn finish_cursor(&mut self) -> Result<Option<FlipStamp>, FsError> {
        let mut stamp = None;
        while self
            .state
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.pending())
        {
            self.ownership_valid()?;
            let done = self
                .state
                .dsb
                .as_mut()
                .ok_or(FsError::NoDevice)?
                .poll(self.device.platform.now())
                .inspect_err(|_| self.state.failed = true)?;
            if !done {
                self.device.platform.tick().await;
                continue;
            }
            self.state
                .cursor
                .as_mut()
                .expect("cursor")
                .complete()
                .inspect_err(|_| self.state.failed = true)?;
            let state = &mut *self.state;
            let dsb = state.dsb.as_mut().expect("cursor DSB");
            stamp = Some(
                dsb.stamp(self.device.platform.now())
                    .inspect_err(|_| state.failed = true)?,
            );
            // Clear armed and restore status only after the independent live
            // cursor witness. A retained idle transport is reusable by color;
            // it must not be mistaken for an outstanding color transaction.
            dsb.shutdown().inspect_err(|_| state.failed = true)?;
        }
        if self.state.cursor.is_some() {
            let enabled = self
                .state
                .cursor
                .as_ref()
                .expect("cursor")
                .resource_enabled();
            if let Some(profile) = self.state.gen12_cursor_profile {
                profile
                    .check_cursor(&self.device.platform, enabled)
                    .inspect_err(|_| self.state.failed = true)?;
            }
            self.state
                .cursor
                .as_ref()
                .expect("cursor")
                .current_valid()
                .inspect_err(|_| self.state.failed = true)?;
        }
        Ok(stamp)
    }
    fn cursor_refused_before_arm(&mut self) {
        if self
            .state
            .cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.exposed() && !cursor.active())
        {
            self.state.cursor = None;
        }
        if self.state.paused
            && !self.state.failed
            && self.state.presenter.is_none()
            && self.state.color.is_none()
            && !self.state.color_owned
            && !self.state.color_unpublished
            && !self.state.mixed_unpublished
            && !self
                .state
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.active())
        {
            self.device.platform.resume_console();
            self.state.paused = false;
        }
    }
    pub(crate) async fn cursor(
        &mut self,
        image: Option<Arc<GemObject>>,
        replace: bool,
        position: Option<(i32, i32)>,
        timing: crate::intel_gpu_dsb::Timing,
    ) -> Result<FlipStamp, FsError> {
        self.cursor_inner(image, replace, position, timing, false)
            .await
    }
    async fn cursor_inner(
        &mut self,
        image: Option<Arc<GemObject>>,
        replace: bool,
        position: Option<(i32, i32)>,
        timing: crate::intel_gpu_dsb::Timing,
        restoring: bool,
    ) -> Result<FlipStamp, FsError> {
        self.ownership_valid()?;
        if !matches!(
            self.device.generation,
            Generation::MeteorLake | Generation::TigerLake | Generation::AlderLake
        ) || !timing.valid()
        {
            return Err(FsError::Unsupported);
        }
        if self
            .state
            .cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.timing_matches(timing))
        {
            return Err(FsError::Unsupported);
        }
        if !restoring && (self.state.mixed_unpublished || self.state.color_unpublished) {
            return Err(FsError::Busy);
        }
        self.finish_color().await?;
        self.finish_pending().await?;
        let family = self.device.platform.gen12_family();
        let profile = if let Some(family) = family {
            self.acquire_gen12_resources()?;
            if self.state.gen12_cursor_profile.is_none() {
                self.state.gen12_cursor_profile =
                    Some(crate::intel_gpu_gen12_cursor_resources::Profile::capture(
                        &self.device.platform,
                        timing,
                        family,
                    )?);
            }
            self.state
                .gen12_cursor_profile
                .expect("Gen12 cursor profile")
                .check(&self.device.platform, family)?;
            None
        } else {
            if self.device.generation != Generation::MeteorLake {
                return Err(FsError::Unsupported);
            }
            Some(crate::intel_gpu_display_resources::Profile::capture_timing(
                &self.device.platform,
                timing,
            )?)
        };
        self.device.platform.takeover(self.state.cursor.is_some())?;
        if self.state.cursor.is_none() {
            let cursor = if let Some(family) = family {
                crate::intel_gpu_cursor::Owner::new_gen12(
                    self.device.platform.clone(),
                    self.device.bar_len,
                    timing,
                    family,
                )?
            } else {
                crate::intel_gpu_cursor::Owner::new(
                    self.device.platform.clone(),
                    self.device.bar_len,
                    timing,
                )?
            };
            self.state.cursor = Some(cursor);
        }
        if !self.state.paused {
            self.state.paused = true;
            self.device.platform.pause_console().await;
        }
        if self.state.dsb.is_none() {
            let reserved = if let Some(profile) = self.state.gen12_cursor_profile {
                crate::intel_gpu_dsb::Owner::reserve_gen12(
                    self.device.platform.clone(),
                    self.device.bar_len,
                    profile.latencies,
                )
            } else {
                crate::intel_gpu_dsb::Owner::reserve(
                    self.device.platform.clone(),
                    self.device.bar_len,
                )
            };
            match reserved {
                Ok(dsb) => self.state.dsb = Some(dsb),
                Err(error) => {
                    if error == FsError::Unsupported {
                        self.cursor_refused_before_arm();
                    } else {
                        self.state.failed = true;
                    }
                    return Err(error);
                }
            }
        }
        let gen12_profile = self.state.gen12_cursor_profile;
        if let Some(profile) = gen12_profile {
            self.state
                .dsb
                .as_ref()
                .expect("DSB")
                .check_gen12_latencies(profile.latencies)?;
        }
        let cursor = self.state.cursor.as_mut().expect("cursor");
        let staged = if let Some(profile) = gen12_profile {
            cursor.stage_with(
                |enabled| profile.cursor_registers(enabled),
                image.as_ref(),
                replace,
                position,
            )
        } else {
            cursor.stage(
                profile.expect("MTL profile"),
                image.as_ref(),
                replace,
                position,
            )
        };
        let regs = match staged {
            Ok(regs) => regs,
            Err(error) => {
                if matches!(error, FsError::Unsupported | FsError::InvalidData) {
                    self.cursor_refused_before_arm();
                } else {
                    self.state.failed = true;
                }
                return Err(error);
            }
        };
        let arm = self.state.dsb.as_mut().expect("DSB").arm(
            timing,
            &regs,
            None,
            self.device.platform.now(),
        );
        if let Err(error) = arm {
            if error == FsError::Unsupported {
                self.state.cursor.as_mut().expect("cursor").cancel_unarmed();
                self.cursor_refused_before_arm();
            } else {
                self.state.failed = true;
            }
            return Err(error);
        }
        self.finish_cursor().await?.ok_or(FsError::NoDevice)
    }
    async fn finish_color(&mut self) -> Result<Option<FlipStamp>, FsError> {
        self.finish_cursor().await?;
        loop {
            self.ownership_valid()?;
            if self.state.dsb.as_ref().is_some_and(|dsb| dsb.armed()) {
                let ready = self
                    .state
                    .dsb
                    .as_mut()
                    .expect("DSB owner")
                    .poll(self.device.platform.now())
                    .inspect_err(|_| {
                        self.state.failed = true;
                    })?;
                if !ready {
                    self.device.platform.tick().await;
                    continue;
                }
                if self
                    .state
                    .joint
                    .as_ref()
                    .is_some_and(|joint| joint.completion.is_none())
                {
                    let completion = self
                        .state
                        .presenter
                        .as_mut()
                        .expect("joint presenter")
                        .poll(self.device.platform.now())
                        .map_err(scanout_error)
                        .inspect_err(|_| self.state.failed = true)?;
                    let Some(completion) = completion else {
                        self.device.platform.tick().await;
                        continue;
                    };
                    self.state.joint.as_mut().expect("joint state").completion = Some(completion);
                }
                let stamp = self
                    .state
                    .dsb
                    .as_ref()
                    .expect("DSB owner")
                    .stamp(self.device.platform.now())
                    .inspect_err(|_| {
                        self.state.failed = true;
                    })?;
                if let Some(resources) = self.state.primary_resources.as_mut() {
                    if resources.pending() {
                        resources
                            .complete(&self.device.platform)
                            .inspect_err(|_| self.state.failed = true)?;
                    }
                }
                if self
                    .state
                    .joint
                    .as_ref()
                    .is_none_or(|joint| !joint.color_complete)
                {
                    let state = &mut *self.state;
                    let update = state.dsb_update.as_ref().expect("DSB color image");
                    state
                        .color
                        .as_mut()
                        .expect("color owner")
                        .complete_dsb(&self.device.platform, update)
                        .inspect_err(|_| {
                            state.failed = true;
                        })?;
                    if let Some(joint) = &mut state.joint {
                        joint.color_complete = true;
                    }
                }
                // The two independent completion records are retained before
                // this final observation. Table verification may span frames;
                // exclusive ownership preserves that image while we bracket
                // primary live/control and visible color arms in ONE stable
                // current hardware frame. Neither a DSB interrupt nor an old
                // primary completion alone may publish the joint state.
                let stamp = if (self.device.platform.gen12_family().is_some()
                    || self.state.xr30_timing.is_some())
                    && self.state.joint.is_some()
                {
                    if let Some(timing) = self.state.xr30_timing {
                        xr30_profile(&self.device.platform, self.console_geometry(), timing)
                            .inspect_err(|_| self.state.failed = true)?;
                    }
                    if let Some(family) = self.device.platform.gen12_family() {
                        let owner = self.state.gen12_primary.as_ref().ok_or(FsError::NoDevice)?;
                        let resources = owner
                            .check_owned(
                                &self.device.platform,
                                self.state.dsb.as_ref().is_some_and(|d| d.exposed()),
                                self.state.cursor.as_ref().is_some_and(|c| c.exposed()),
                            )
                            .and_then(|()| {
                                owner.check_console_mapping(
                                    &self.device.platform,
                                    &self.state.console,
                                )
                            });
                        resources.inspect_err(|_| self.state.failed = true)?;
                        self.state
                            .gen12_cursor_profile
                            .ok_or(FsError::NoDevice)?
                            .check(&self.device.platform, family)
                            .inspect_err(|_| self.state.failed = true)?;
                    }
                    let joint = self.state.joint.as_ref().expect("joint state");
                    let completion = joint.completion.expect("independent primary completion");
                    let observed = self
                        .state
                        .presenter
                        .as_ref()
                        .expect("joint presenter")
                        .observe_completed(&completion, self.device.platform.now())
                        .map_err(scanout_error)
                        .inspect_err(|_| self.state.failed = true)?;
                    self.state
                        .color
                        .as_ref()
                        .expect("color owner")
                        .check_visible(&self.device.platform)
                        .inspect_err(|_| self.state.failed = true)?;
                    let after = self
                        .state
                        .dsb
                        .as_ref()
                        .expect("DSB owner")
                        .stamp(self.device.platform.now())
                        .inspect_err(|_| self.state.failed = true)?;
                    if observed.is_none_or(|before| before.sequence != after.sequence) {
                        if self.device.platform.now()
                            >= self.state.joint.as_ref().expect("joint").deadline
                        {
                            self.state.failed = true;
                            return Err(FsError::TimedOut);
                        }
                        self.device.platform.tick().await;
                        continue;
                    }
                    after
                } else {
                    stamp
                };
                if self.state.joint.is_some() {
                    if let Some(owner) = self.state.gen12_primary.as_mut() {
                        owner
                            .complete_view(&self.device.platform)
                            .inspect_err(|_| self.state.failed = true)?;
                    }
                }
                self.state
                    .dsb
                    .as_mut()
                    .expect("DSB owner")
                    .shutdown()
                    .inspect_err(|_| {
                        self.state.failed = true;
                    })?;
                self.state.dsb_update = None;
                let stamp = if let Some(joint) = self.state.joint.take() {
                    let completion = joint.completion.expect("joint primary latch");
                    if let Some(retired) = completion.retired {
                        self.state
                            .presenter
                            .as_mut()
                            .expect("joint presenter")
                            .release(retired)
                            .map_err(scanout_error)
                            .inspect_err(|_| self.state.failed = true)?;
                    }
                    self.state.current = self.state.pending.take();
                    if self.device.platform.gen12_family().is_some()
                        || self.state.xr30_timing.is_some()
                    {
                        stamp
                    } else {
                        completion.stamp
                    }
                } else {
                    stamp
                };
                // Both independent completions, exact target and final common
                // frame precede retirement of the XR30-only qualification.
                // The existing XR24 X/Tile4 lane is then unconstrained again.
                if self
                    .state
                    .presenter
                    .as_ref()
                    .is_some_and(|p| !p.tracks_xr30())
                {
                    self.state.xr30_timing = None;
                    self.state.xr30_epoch = None;
                }
                return Ok(Some(stamp));
            }

            let Some(color) = self.state.color.as_mut() else {
                return Ok(None);
            };
            if !color.pending() {
                return Ok(None);
            }
            match color.poll(&self.device.platform, self.device.platform.now()) {
                Ok(Some(stamp)) => return Ok(Some(stamp)),
                Ok(None) => self.device.platform.tick().await,
                Err(error) => {
                    self.state.failed = true;
                    return Err(error);
                }
            }
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) async fn set_ctm(
        &mut self,
        coefficients: Option<[u64; 9]>,
    ) -> Result<FlipStamp, FsError> {
        self.set_color(coefficients, None).await
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) async fn set_color(
        &mut self,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
    ) -> Result<FlipStamp, FsError> {
        self.set_color_with_dsb(coefficients, lut, None, None).await
    }
    pub(crate) async fn set_color_with_dsb(
        &mut self,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        degamma: Option<Arc<crate::intel_gpu_color::DegammaLut>>,
        dsb_timing: Option<crate::intel_gpu_dsb::Timing>,
    ) -> Result<FlipStamp, FsError> {
        self.reconcile_unexposed_xr30();
        if self.state.mixed_unpublished {
            return Err(FsError::Busy);
        }
        self.color_transaction(coefficients, lut, degamma, dsb_timing, None)
            .await
    }
    pub(crate) async fn present_color(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
        view: crate::intel_gpu_scanout::View,
        coefficients: Option<[u64; 9]>,
        luts: crate::intel_gpu_color::Luts,
        timing: crate::intel_gpu_dsb::Timing,
    ) -> Result<FlipStamp, FsError> {
        self.reconcile_unexposed_xr30();
        self.check(geometry)?;
        if self.state.color_unpublished || self.state.mixed_unpublished {
            return Err(FsError::Busy);
        }
        if !object.is_wc() || !object.scanout() || object.is_vram() || object.is_userptr() {
            return Err(FsError::Unsupported);
        }
        let xr30 = view.input == crate::intel_gpu_scanout::InputFormat::Xrgb2101010
            || self
                .state
                .presenter
                .as_ref()
                .is_some_and(|p| p.tracks_xr30());
        if xr30 {
            if self.device.generation != Generation::MeteorLake
                || view.layout != crate::intel_gpu_scanout::Layout::Linear
                || self.state.current.as_ref().is_some_and(|(_, id)| {
                    !self
                        .state
                        .presenter
                        .as_ref()
                        .expect("presenter")
                        .linear_surface(*id)
                })
            {
                return Err(FsError::Unsupported);
            }
            xr30_profile(&self.device.platform, geometry, timing)?;
            if let Some(presenter) = &self.state.presenter {
                presenter.check_current(geometry).map_err(scanout_error)?;
            }
            if let Some(color) = &self.state.color {
                color.check_visible(&self.device.platform)?;
            }
            if self.state.xr30_timing.is_some_and(|old| old != timing) {
                return Err(FsError::Unsupported);
            }
        }
        let alignment = self
            .device
            .platform
            .gen12_family()
            .map_or(4096, crate::intel_gpu_scanout::gen12_alignment);
        let (_, _, extent) = view
            .footprint_aligned(geometry, alignment)
            .map_err(scanout_error)?;
        if let Some(family) = self.device.platform.gen12_family() {
            if geometry.pitch > crate::intel_gpu_scanout::gen12_max_stride(family) {
                return Err(FsError::Unsupported);
            }
        }
        if extent > object.size() {
            return Err(FsError::InvalidData);
        }
        if view.layout != crate::intel_gpu_scanout::Layout::Linear {
            tiled_profile(&self.device.platform, geometry, timing, view.layout)?;
            if view.layout == crate::intel_gpu_scanout::Layout::Tile4
                && self.state.primary_resources.is_none()
            {
                // Prove target WM/min-DDB fit before any new GEM mapping.
                crate::intel_gpu_display_resources::Primary::capture(
                    &self.device.platform,
                    timing,
                )?;
            }
        }
        let previous_timing = self.state.xr30_timing;
        let previous_epoch = self.state.xr30_epoch;
        if xr30 {
            let epoch = xr30_profile(&self.device.platform, geometry, timing)?;
            if previous_epoch.is_some_and(|old| old != epoch) {
                return Err(FsError::NoDevice);
            }
            self.state.xr30_timing = Some(timing);
            self.state.xr30_epoch = Some(epoch);
        }
        let result = self
            .color_transaction(
                coefficients,
                luts.post,
                luts.pre,
                Some(timing),
                Some(PrimaryTarget {
                    object,
                    geometry,
                    view,
                }),
            )
            .await;
        // A strict unexposed refusal has already rolled back its new mapping
        // and pending state. Never leave an XR30-only constraint on the old
        // supported XR24 tiling lane. Failure/cancellation uncertainty keeps it.
        if result.is_err()
            && !self.state.failed
            && !self.state.mixed_unpublished
            && self.state.joint.is_none()
            && self.state.pending.is_none()
            && !self
                .state
                .presenter
                .as_ref()
                .is_some_and(|p| p.tracks_xr30())
        {
            self.state.xr30_timing = previous_timing;
            self.state.xr30_epoch = previous_epoch;
        }
        result
    }
    async fn color_transaction(
        &mut self,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        degamma: Option<Arc<crate::intel_gpu_color::DegammaLut>>,
        dsb_timing: Option<crate::intel_gpu_dsb::Timing>,
        primary: Option<PrimaryTarget>,
    ) -> Result<FlipStamp, FsError> {
        // Gen12 joint qualification is fixed linear/origin-zero only. The
        // worker still acquires exact family, route, DDB/WM and console proofs;
        // a Card capability alone cannot authorize a command or scanout write.
        if self.device.generation != Generation::MeteorLake
            && (self.device.platform.gen12_family().is_none()
                || primary.as_ref().is_some_and(|target| {
                    target.view.layout == crate::intel_gpu_scanout::Layout::Tile4
                        || target.view.input != crate::intel_gpu_scanout::InputFormat::Xrgb8888
                }))
        {
            return Err(FsError::Unsupported);
        }
        self.ownership_valid()?;
        self.finish_color().await?;
        self.finish_pending().await?;
        let previously_owned = self.state.color_owned;
        let had_presenter = self.state.presenter.is_some();
        let had_primary_resources = self.state.primary_resources.is_some();
        let previous_mixed = self.state.mixed_unpublished;
        if self.state.color.is_none() {
            let owner = if let Some(family) = self.device.platform.gen12_family() {
                crate::intel_gpu_color::Owner::capture_gen12(&self.device.platform, family)?
            } else {
                crate::intel_gpu_color::Owner::capture(
                    &self.device.platform,
                    self.device.generation,
                )?
            };
            self.state.color = Some(owner);
        }
        if !self.state.color_owned {
            self.state.paused = true;
            self.device.platform.pause_console().await;
            if let Err(error) = self
                .device
                .platform
                .color_takeover(self.state.cursor.is_some())
            {
                // The original was retained before pausing; no CSC write has
                // occurred. Lost authority keeps the owner quarantined.
                if self.device.platform.reset_lost() {
                    self.state.failed = true;
                } else {
                    self.state.color = None;
                    self.state.color_owned = false;
                    if self.state.presenter.is_none()
                        && !self
                            .state
                            .cursor
                            .as_ref()
                            .is_some_and(|cursor| cursor.active())
                    {
                        self.device.platform.resume_console();
                        self.state.paused = false;
                    }
                }
                return Err(error);
            }
            self.acquire_gen12_resources()?;
            self.state.color_owned = true;
        }
        let unpublished = core::mem::replace(&mut self.state.color_unpublished, true);
        let mut exposed_preload = false;
        let arm = if let Some(timing) = dsb_timing {
            async {
                self.device.platform.takeover(self.state.cursor.is_some())?; // live PAT/GT + PSR ownership
                let gen12_color = self
                    .device
                    .platform
                    .gen12_family()
                    .map(crate::intel_gpu_color::Profile::gen12);
                if let Some(profile) = gen12_color {
                    self.acquire_gen12_resources()?;
                    let family = self
                        .device
                        .platform
                        .gen12_family()
                        .ok_or(FsError::NoDevice)?;
                    if self.state.gen12_cursor_profile.is_none() {
                        self.state.gen12_cursor_profile =
                            Some(crate::intel_gpu_gen12_cursor_resources::Profile::capture(
                                &self.device.platform,
                                timing,
                                family,
                            )?);
                    }
                    self.state
                        .gen12_cursor_profile
                        .expect("Gen12 resources")
                        .check(&self.device.platform, family)?;
                    self.state
                        .color
                        .as_mut()
                        .expect("color owner")
                        .qualify_gen12(profile)?;
                }
                if self.state.dsb.is_none() {
                    let dsb = if let Some(resources) = self.state.gen12_cursor_profile {
                        crate::intel_gpu_dsb::Owner::reserve_gen12(
                            self.device.platform.clone(),
                            self.device.bar_len,
                            resources.latencies,
                        )
                    } else {
                        crate::intel_gpu_dsb::Owner::reserve(
                            self.device.platform.clone(),
                            self.device.bar_len,
                        )
                    }
                    .map_err(|error| {
                        if error == FsError::NotImplemented {
                            FsError::Unsupported
                        } else {
                            error
                        }
                    })?;
                    self.state.dsb = Some(dsb);
                }
                if let Some(profile) = gen12_color {
                    let latencies = self
                        .state
                        .gen12_cursor_profile
                        .expect("Gen12 resources")
                        .latencies;
                    let dsb = self.state.dsb.as_mut().expect("DSB");
                    dsb.check_gen12_latencies(latencies)?;
                    dsb.qualify_gen12_color(profile)?;
                }
                if self
                    .state
                    .color
                    .as_ref()
                    .expect("color owner")
                    .needs_inactive_preload(lut.as_deref(), degamma.as_deref())
                {
                    let update = self
                        .state
                        .color
                        .as_mut()
                        .expect("color owner")
                        .prepare_inactive_preload(
                            &self.device.platform,
                            lut.clone(),
                            degamma.clone(),
                        )?;
                    self.state.dsb_update = Some(update);
                    {
                        let state = &mut *self.state;
                        let update = state.dsb_update.as_ref().expect("preload image");
                        let armed = state.dsb.as_mut().expect("DSB").arm_color(
                            timing,
                            &[],
                            update.lut(),
                            update.degamma(),
                            self.device.platform.now(),
                        );
                        if armed != Err(FsError::Unsupported) {
                            exposed_preload = true;
                            state
                                .color
                                .as_mut()
                                .expect("color owner")
                                .expose_dsb(update);
                            state.gen12_lut_ram_owned |= state
                                .color
                                .as_ref()
                                .expect("color owner")
                                .owns_unreadable_ram();
                        }
                        armed?;
                    }
                    // finish_color consumes the retained preload image exactly
                    // like any cancelled/in-flight stream. No target enable is
                    // present in this first command buffer.
                    self.finish_color().await?;
                }
                let surface = if let Some(PrimaryTarget {
                    object,
                    geometry,
                    view,
                }) = &primary
                {
                    self.start().await?;
                    if view.layout == crate::intel_gpu_scanout::Layout::Tile4
                        && self.state.primary_resources.is_none()
                    {
                        self.state.primary_resources =
                            Some(crate::intel_gpu_display_resources::Primary::capture(
                                &self.device.platform,
                                timing,
                            )?);
                    }
                    let id = self.prepare_surface(object.clone(), *geometry, *view)?;
                    let ticket = self.ticket()?;
                    self.state.pending = Some((object.clone(), id));
                    self.state.mixed_unpublished = true;
                    self.state.joint = Some(Joint {
                        staged: false,
                        completion: None,
                        color_complete: false,
                        deadline: self.device.platform.now().saturating_add(1_000_000_000),
                    });
                    if let Some(owner) = self.state.gen12_primary.as_mut() {
                        owner.stage_view(&self.device.platform, *view)?;
                    }
                    let mut arm = self
                        .state
                        .presenter
                        .as_mut()
                        .expect("joint presenter")
                        .stage_dsb(id, ticket, self.device.platform.now())
                        .map_err(scanout_error)?;
                    self.state.joint.as_mut().expect("joint state").staged = true;
                    if let Some(resources) = self.state.primary_resources.as_mut() {
                        arm.extend(resources.stage(
                            &self.device.platform,
                            view.layout == crate::intel_gpu_scanout::Layout::Tile4,
                        )?);
                    }
                    Some(arm)
                } else {
                    None
                };
                let mut update = self
                    .state
                    .color
                    .as_mut()
                    .expect("color owner")
                    .prepare_stages(
                        &self.device.platform,
                        coefficients,
                        lut.clone(),
                        degamma.clone(),
                    )?;
                if self.device.generation == Generation::MeteorLake {
                    if let Some(target) = &primary {
                        self.state
                            .color
                            .as_ref()
                            .expect("color owner")
                            .target_input(&mut update, target.view.input)?;
                    }
                }
                if let Some(surface) = surface {
                    update.registers.extend(surface);
                }
                self.state.dsb_update = Some(update);
                let state = &mut *self.state;
                let update = state.dsb_update.as_ref().expect("DSB color image");
                let armed = state.dsb.as_mut().expect("DSB owner").arm_color(
                    timing,
                    &update.registers,
                    update.lut(),
                    update.degamma(),
                    self.device.platform.now(),
                );
                if armed != Err(FsError::Unsupported) {
                    state
                        .color
                        .as_mut()
                        .expect("color owner")
                        .expose_dsb(update);
                    state.gen12_lut_ram_owned |= state
                        .color
                        .as_ref()
                        .expect("color owner")
                        .owns_unreadable_ram();
                }
                armed
            }
            .await
        } else {
            self.state.color.as_mut().expect("color owner").arm_stages(
                &self.device.platform,
                coefficients,
                lut.clone(),
                degamma.clone(),
                self.device.platform.now(),
            )
        };
        if let Err(error) = arm {
            // Unsupported is confined to preflight before this attempt
            // writes command memory, PTEs, or controls. Preserve a parked
            // installed BO/VA while unwinding this unexposed color update.
            let prewrite = !exposed_preload
                && error == FsError::Unsupported
                && self.state.dsb.as_ref().is_none_or(|dsb| !dsb.armed());
            if prewrite {
                self.rollback_joint_before_arm()?;
                if let Some(resources) = self.state.primary_resources.as_mut() {
                    resources.rollback();
                }
                if !had_primary_resources {
                    self.state.primary_resources = None;
                }
                self.state.mixed_unpublished = previous_mixed;
                if self.state.dsb.as_ref().is_some_and(|dsb| !dsb.exposed()) {
                    self.state.dsb = None;
                }
                self.state.dsb_update = None;
                self.state
                    .color
                    .as_mut()
                    .expect("color owner")
                    .cancel_dsb_before_arm();
            }
            // Owner's Unsupported branch is strictly before any IO: an
            // abandoned LUT may still be active although Card never published
            // it. Keep that uncertainty, but permit an explicit clear/restore.
            // Palette/control writes and every other failure quarantine it.
            if prewrite {
                self.state.color_unpublished = unpublished;
                if !previously_owned {
                    // This owner captured only untouched inherited baseline;
                    // no color arm/palette write was exposed by this attempt.
                    self.state.color = None;
                    self.state.color_owned = false;
                    if self.state.presenter.is_none()
                        && !self
                            .state
                            .cursor
                            .as_ref()
                            .is_some_and(|cursor| cursor.active())
                    {
                        self.device.platform.resume_console();
                        self.state.paused = false;
                    }
                }
                if !had_presenter && self.state.presenter.is_some() {
                    self.restore_surface().await?;
                }
            } else {
                self.state.failed = true;
            }
            return Err(error);
        }
        let stamp = self.finish_color().await?.ok_or(FsError::NoDevice)?;
        if coefficients.is_none()
            && lut.is_none()
            && degamma.is_none()
            && !self
                .state
                .presenter
                .as_ref()
                .is_some_and(|p| p.tracks_xr30())
        {
            self.state.color = None;
            self.state.color_owned = false;
            if self.state.presenter.is_none()
                && !self.state.cursor.as_ref().is_some_and(|c| c.active())
            {
                self.state.gen12_primary = None;
            }
            if self.state.presenter.is_none()
                && self.state.paused
                && !self
                    .state
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| cursor.active())
            {
                self.device.platform.resume_console();
                self.state.paused = false;
            }
        }
        Ok(stamp)
    }
    /// The KMS publisher calls this while still holding this session and its
    /// final Card lock, after copying the hardware-complete CTM into Card.
    pub(crate) fn confirm_ctm(&mut self) {
        debug_assert!(self
            .state
            .color
            .as_ref()
            .is_none_or(|color| !color.pending()));
        self.state.color_unpublished = false;
        self.state.mixed_unpublished = false;
    }
    async fn restore_color(&mut self) -> Result<(), FsError> {
        self.reconcile_unexposed_xr30();
        self.finish_color().await?;
        if self.state.color.is_some() {
            // Internal full restoration may clear color while keeping the
            // mixed marker until independent primary restoration also ends.
            self.color_transaction(None, None, None, None, None).await?;
        }
        self.state.color_unpublished = false;
        Ok(())
    }
    pub(crate) async fn wait_vblank(&mut self) -> Result<FlipStamp, FsError> {
        if self.state.presenter.is_some() || self.state.failed || self.state.mixed_unpublished {
            return Err(FsError::Busy);
        }
        let start = self.device.platform.read32(0x70040);
        let deadline = self
            .device
            .platform
            .now()
            .checked_add(1_000_000_000)
            .ok_or(FsError::Busy)?;
        loop {
            if !self.device.platform.console_access_ok() {
                return Err(FsError::NoDevice);
            }
            let before = self.device.platform.read32(0x70040);
            let after = self.device.platform.read32(0x70040);
            if before != u32::MAX && before == after && before != start {
                return Ok(FlipStamp {
                    ns: self.device.platform.now(),
                    sequence: before,
                });
            }
            if self.device.platform.now() >= deadline {
                return Err(crate::intel_gpu_user::io_error());
            }
            self.device.platform.tick().await;
        }
    }
}

#[path = "intel_gpu_gen12_display.rs"]
mod gen12_primary;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_kms_tests.rs"]
pub(crate) mod tests;
