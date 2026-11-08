//! Per-card fixed-mode Intel KMS transactions. The async mutex is outermost:
//! no Card/CONTROLLER/IRQ spinlock may survive a hardware-latch await.
//! Display DMA owns front and pending GEM pages until independent retirement.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
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
type PanelWait<'a> = Pin<Box<dyn Future<Output = Result<(), FsError>> + Send + 'a>>;
type DisplayWakeref = crate::intel_gpu_gt_runtime::display_rpm::Wakeref;
type RpmWait<'a> =
    Pin<Box<dyn Future<Output = Result<Option<DisplayWakeref>, FsError>> + Send + 'a>>;

fn x_tiled_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
) -> Result<(), FsError> {
    tiled_profile(io, geometry, timing, crate::intel_gpu_scanout::Layout::X).map(|_| ())
}
/// The display IP the KMS owner of `generation` proves its resources on.
fn resource_ip(generation: Generation) -> crate::intel_gpu_xe2lpd::DisplayIp {
    match generation {
        Generation::LunarLake => crate::intel_gpu_xe2lpd::DisplayIp::Xe2Lpd,
        Generation::PantherLake => crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd,
        _ => crate::intel_gpu_xe2lpd::DisplayIp::Xelpdp,
    }
}
/// The tiled primary's admission; the proved display IP, `None` on Gen12.
fn tiled_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
    layout: crate::intel_gpu_scanout::Layout,
) -> Result<Option<crate::intel_gpu_xe2lpd::DisplayIp>, FsError> {
    if !io.console_access_ok() {
        return Err(FsError::NoDevice);
    }
    if let Some(family) = io.gen12_family() {
        return gen12_primary::view_profile(io, geometry, timing, family, layout).map(|()| None);
    }
    crate::intel_gpu_scanout::View {
        origin: Default::default(),
        layout,
        input: Default::default(),
    }
    .footprint(geometry)
    .map_err(scanout_error)?;
    let profile = crate::intel_gpu_display_resources::Profile::capture_timing(io, timing)?;
    // Display 14 scans the tiled primary out directly behind the owned
    // PLANE_CHICKEN no-DPT bit. Display 20 has none (intel_dpt_configure):
    // the presenter fetches it through its own DPT, whose POT-remapped
    // layout must hold for this geometry.
    if profile.ip.has_no_dpt_chicken() {
        let chicken = io.read32(0x7026c);
        if chicken == u32::MAX {
            return Err(FsError::NoDevice);
        }
        if chicken & (1 << 19) == 0 {
            return Err(FsError::Unsupported);
        }
    } else if crate::intel_gpu_scanout::DptLayout::new(geometry, layout).is_none() {
        return Err(FsError::Unsupported);
    }
    if !io.console_access_ok() {
        return Err(FsError::NoDevice);
    }
    Ok(Some(profile.ip))
}
pub(crate) fn tile4_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
) -> Result<(), FsError> {
    let ip = tiled_profile(
        io,
        geometry,
        timing,
        crate::intel_gpu_scanout::Layout::Tile4,
    )?
    .ok_or(FsError::Unsupported)?;
    crate::intel_gpu_display_resources::Primary::capture_ip(io, timing, ip)?;
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
    timing.check(io, None, false)?;
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

/// Display 13 (ADL-P, ADL-N): the Gen12 orchestrator writes
/// `TRANS_VBLANK` without its start field there.
fn gen12_display13(io: &impl Platform) -> bool {
    use crate::intel_gpu_gt::Gen12Platform;
    matches!(
        io.gen12_family(),
        Some(Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN)
    )
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
    /// Poll the display-14 FBC CFB carve for `size` bytes (1:1) in DSM:
    /// `Ready(Some((DSM offset, placed bytes, compression limit)))`,
    /// `Ready(None)` when nothing can be placed, or `Pending` while the
    /// carve (with its GGTT aperture survey) runs off the present path.
    /// Never blocks and never surveys. Default: no FBC.
    fn fbc_carve(&self, _size: u64, _min_limit: u32) -> Poll<Option<(u32, u64, u32)>> {
        Poll::Ready(None)
    }
    /// A view that may reach registers while a GT-reset loss is being
    /// recovered, used only to stop an owned FBC before recovery's
    /// inherited-fetcher inventory. Default: none.
    fn fbc_recovery_view(&self) -> Option<Self> {
        None
    }
    /// Display-14 KMS-owned PSR: the fixed Pipe-A panel timing PSR
    /// qualifies against. Default: none, so PSR is never offered.
    fn psr_timing(&self) -> Option<crate::intel_gpu_dsb::Timing> {
        None
    }
    /// One native AUX transaction to the Pipe-A eDP sink, through this
    /// window. Default: no sink.
    fn psr_aux<'a>(
        &self,
        _request: &crate::dp_aux::AuxRequest<'_>,
        _reply: &'a mut [u8],
    ) -> Result<crate::dp_aux::AuxResponse<'a>, crate::dp_aux::AuxError> {
        Err(crate::dp_aux::AuxError::Nacked)
    }
    /// Wa_14015648006's Pipe-A `wm_level_disabled` for the watermarks the
    /// caller just proved programmed. Default: unknown, which refuses PSR.
    fn psr_wm_level_disabled(&self) -> Option<bool> {
        None
    }
    /// The Pipe-A eDP PSR VBT facts. Default: no VBT, which refuses PSR.
    fn psr_vbt(&self) -> crate::intel_gpu_psr::VbtPsr {
        crate::intel_gpu_psr::VbtPsr::Missing
    }
    /// PCI device, subsystem vendor and subsystem device, which
    /// `QUIRK_FW_SYNC_LEN` matches. Default: unknown, which refuses PSR2.
    fn psr_pci_ids(&self) -> Option<(u16, u16, u16)> {
        None
    }
    /// `intel_display_rpm_get` for one KMS session
    /// (`xe_pm_runtime_resume_and_get`): a runtime-PM reference that
    /// resumes the function first, held for the session. Default: none.
    fn display_rpm(&self) -> RpmWait<'_> {
        Box::pin(async { Ok(None) })
    }
    /// The panel's crtc off after the owner's pre-plane update: planes,
    /// backlight, transcoder, port, PPS, PLL, pipe DMC, post-plane settle.
    /// Default: the platform cannot turn its panel off.
    fn panel_off(&self) -> PanelWait<'_> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// The panel's crtc on again at its mode, scanning out `console`.
    fn panel_on<'a>(&'a self, _console: &'a ActiveScanout) -> PanelWait<'a> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
}

/// The Pipe-A eDP sink as an AUX channel over a platform window.
struct PsrAux<'a, M: Platform>(&'a M);
impl<M: Platform> crate::dp_aux::AuxChannel for PsrAux<'_, M> {
    fn transact<'b>(
        &mut self,
        request: &crate::dp_aux::AuxRequest<'_>,
        reply: &'b mut [u8],
    ) -> Result<crate::dp_aux::AuxResponse<'b>, crate::dp_aux::AuxError> {
        self.0.psr_aux(request, reply)
    }
}

/// `intel_psr_disable_locked` on the KMS-owned PSR through `regs`, then
/// latch `cause` when it must hold. A sink that reported an error is woken
/// (`intel_psr_handle_irq`).
fn psr_disable<M: Platform>(
    state: &mut State<M>,
    regs: &M,
    cause: Option<crate::intel_gpu_psr::Refusal>,
) {
    use crate::intel_gpu_psr::{Refusal, PSR_EXIT_TIMEOUT_MS};
    let mut latch = cause.filter(|c| c.latched());
    if let Some(mut psr) = state.psr.take() {
        let wake = cause == Some(Refusal::SinkNotReliable);
        if let Err(refusal) = psr.disable(regs, &mut PsrAux(regs), PSR_EXIT_TIMEOUT_MS, wake) {
            if refusal.latched() {
                latch.get_or_insert(refusal);
            }
        }
    }
    if latch.is_some() {
        state.psr_refused = latch;
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
    /// Panther Lake only: the install proved display 30.00 behind the
    /// opted-in route. `None` on every other generation.
    display30: Option<Display30>,
    /// Shared by every retained PollIo clone. A GT reset invalidates all
    /// outstanding display/cache witnesses; reset alone never retires DMA.
    reset_lost: Arc<AtomicBool>,
    recovering: bool,
    /// The off-path FBC CFB carve, shared by every clone.
    fbc_carve: Arc<crate::intel_gpu_stolen::CarveSlot>,
}
/// What a Panther Lake KMS owner's install proved about display 30.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Display30 {
    /// Wa_15015404425 still applies (`intel_gpu_xe3lpd::wa_15015404425`:
    /// a media GT before B0).
    flush: bool,
}

impl Physical {
    fn read64(&self, offset: u64) -> u64 {
        u64::from(self.read32(offset)) | (u64::from(self.read32(offset + 4)) << 32)
    }
    /// The display-14 DSM layout (`detect_bar2_integrated`) and the
    /// number of CPU-aperture GGTT entries to survey. `Err` when access
    /// is lost (retry later); `Ok(None)` when there is no usable DSM.
    fn fbc_dsm(&self) -> Result<Option<(crate::intel_gpu_stolen::Layout, u64)>, ()> {
        use crate::intel_gpu_stolen as dsm;
        if self.generation != Generation::MeteorLake {
            return Ok(None);
        }
        if !self.access_ok() {
            return Err(());
        }
        let Some((gmadr_base, gmadr_len)) =
            crate::intel_gpu::with_controller(|gpu| (gpu.gmadr.phys.raw(), gpu.gmadr.len))
        else {
            return Ok(None);
        };
        let config = |offset| narf_bus::pci::read_config32(&self.cap, &self.device, offset).ok();
        let (Some(bsm_dw0), Some(bsm_dw1)) = (config(dsm::PCI_BSM_DW0), config(dsm::PCI_BSM_DW1))
        else {
            return Ok(None);
        };
        // detect_bar2_integrated reads GSCPSMI_BASE only for a media GT
        // that takes Wa_14019821291 (media_gt && XE_GT_WA(media_gt, ..)).
        let media_gmd_id = self.read32(dsm::MEDIA_GMD_ID);
        let gscpsmi_base = if dsm::wa_14019821291(media_gmd_id) == Ok(true) {
            self.read64(dsm::MEDIA_GSCPSMI_BASE)
        } else {
            0
        };
        let layout = dsm::layout(dsm::Facts {
            ggc: self.read32(dsm::GGC),
            stolen_reserved_lo: self.read32(dsm::STOLEN_RESERVED),
            media_gmd_id,
            gscpsmi_base,
            gmadr_base,
            gmadr_len,
            bsm_dw0,
            bsm_dw1,
        });
        if !self.access_ok() {
            return Err(());
        }
        // Every DSM page a CPU can reach through the aperture: present DM
        // PTEs in GGTT [0, BAR2 length). This covers the boot framebuffer.
        let entries = (gmadr_len / dsm::PAGE).min(self.bar.len.saturating_sub(GGTT_ARRAY_BASE) / 8);
        Ok(layout.ok().map(|layout| (layout, entries)))
    }
}

/// The off-path FBC carve for one display-14 function: the GGTT aperture
/// survey in [`crate::intel_gpu_stolen::CARVE_CHUNK_PTES`] chunks, each
/// under the KMS mutex (the window's contract) and followed by a yield,
/// then the CFB placement outside it. A KMS session never waits for it.
async fn fbc_carve_job(platform: Physical, size: u64, min_limit: u32) {
    let slot = platform.fbc_carve.clone();
    match fbc_carve_run(&platform, size, min_limit).await {
        Ok(placed) => slot.finish(size, min_limit, placed),
        Err(()) => slot.abandon(),
    }
}
async fn fbc_carve_run(
    platform: &Physical,
    size: u64,
    min_limit: u32,
) -> Result<Option<(u32, u64, u32)>, ()> {
    use crate::intel_gpu_stolen::{Carve, CARVE_CHUNK_PTES};
    let display = display(platform.index).ok_or(())?;
    let mut carve: Option<Carve> = None;
    loop {
        let done = {
            let state = display.state.lock().await;
            if state.failed || platform.reset_lost() {
                return Err(());
            }
            let carve = match carve.as_mut() {
                Some(carve) => carve,
                None => match platform.fbc_dsm()? {
                    Some((layout, entries)) => carve.insert(Carve::new(layout, entries)),
                    None => return Ok(None),
                },
            };
            let done = carve.survey(CARVE_CHUNK_PTES, |index| {
                platform.read64(GGTT_ARRAY_BASE + 8 * index)
            });
            if !platform.access_ok() {
                return Err(());
            }
            drop(state);
            done
        };
        if done {
            break;
        }
        narf_scheduler::yield_now().await;
    }
    Ok(carve.and_then(|carve| {
        carve.place(size, min_limit, |phys| {
            narf_memory::frame::is_system_ram(narf_memory::PhysAddr::new(phys))
        })
    }))
}
impl MmioWindow for Physical {
    fn read32(&self, offset: u64) -> u32 {
        if self.reset_lost() && !self.recovering {
            u32::MAX
        } else {
            // xe_mmio.c::mmio_flush_pending_writes, Wa_15015404425
            // (xe_device_wa_oob.rules: PLATFORM(LUNARLAKE)): four dummy
            // writes precede every read, display reads included.
            if self.generation == Generation::LunarLake
                || self.display30.is_some_and(|display| display.flush)
            {
                for _ in 0..4 {
                    self.window.write32(0x130030, 0);
                }
            }
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
        // The GEM scanout PAT index (`display_pte`) must be the GT owner's
        // programmed entry: MTL PAT1 = XELPG_PAT_1_WT, Xe2 PAT3 =
        // XE2_PAT(0, 0, 0, 3, 3, 0), and display 30's Xe3 PAT3 (the same
        // entry in xe3_lpg_pat_table).
        self.console_access_ok()
            && match self.generation {
                Generation::MeteorLake => self.read32(0x4804) == 4,
                Generation::LunarLake => self.read32(0x480c) == 0x3c,
                Generation::PantherLake => self.display30.is_some() && self.read32(0x480c) == 0x3c,
                _ => true,
            }
    }

    fn display_ip(&self) -> Option<crate::intel_gpu_xe2lpd::DisplayIp> {
        self.display30
            .map(|_| crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd)
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
            if matches!(
                self.generation,
                Generation::MeteorLake | Generation::LunarLake | Generation::PantherLake
            ) {
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
        fetchers_with_cursor(self, fetcher_generation(self), false, owned_cursor)?;
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
        fetchers_with_cursor(self, fetcher_generation(self), false, owned_cursor)?;
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
    fn fbc_carve(&self, size: u64, min_limit: u32) -> Poll<Option<(u32, u64, u32)>> {
        if self.generation != Generation::MeteorLake {
            return Poll::Ready(None);
        }
        self.fbc_carve.poll(size, min_limit, || {
            narf_scheduler::spawn(fbc_carve_job(self.clone(), size, min_limit));
        })
    }
    fn fbc_recovery_view(&self) -> Option<Self> {
        let mut view = self.clone();
        view.recovering = true;
        view.access_ok().then_some(view)
    }
    fn psr_timing(&self) -> Option<crate::intel_gpu_dsb::Timing> {
        if self.generation != Generation::MeteorLake {
            return None;
        }
        let card = crate::drm_registry::mode_state(self.index)?;
        let card = card.lock();
        let mode = card.crtcs.first()?.mode?;
        let wire = card.mode_wire(&mode);
        Some(crate::intel_gpu_dsb::Timing {
            clock: wire.clock,
            width: wire.hdisplay,
            height: wire.vdisplay,
            htotal: wire.htotal,
            vtotal: wire.vtotal,
            flags: wire.flags,
        })
    }
    fn psr_aux<'a>(
        &self,
        request: &crate::dp_aux::AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<crate::dp_aux::AuxResponse<'a>, crate::dp_aux::AuxError> {
        use crate::dp_aux::AuxChannel as _;
        if self.generation != Generation::MeteorLake {
            return Err(crate::dp_aux::AuxError::Nacked);
        }
        // XELPDP AUX_A is the DDI A block (XeLpgPort::A.aux_base()).
        crate::intel_gpu_aux::IntelAux::new(self, crate::intel_gpu_ddi::Ddi::A)
            .transact(request, reply)
    }
    fn psr_wm_level_disabled(&self) -> Option<bool> {
        crate::intel_gpu_psr::wm_level_disabled()
    }
    fn psr_vbt(&self) -> crate::intel_gpu_psr::VbtPsr {
        crate::intel_gpu_psr::installed_vbt()
    }
    fn psr_pci_ids(&self) -> Option<(u16, u16, u16)> {
        Some((
            self.device.id.device,
            self.device.id.subsystem_vendor,
            self.device.id.subsystem_id,
        ))
    }
    fn display_rpm(&self) -> RpmWait<'_> {
        Box::pin(async move {
            crate::intel_gpu_gt_runtime::display_rpm::wakeref_resume(self.bar.phys.raw())
                .await
                .map_err(|_| FsError::NoDevice)
        })
    }
    fn panel_off(&self) -> PanelWait<'_> {
        Box::pin(async move {
            if self.generation != Generation::MeteorLake {
                return Err(FsError::Unsupported);
            }
            panel_power_off(self).await
        })
    }
    fn panel_on<'a>(&'a self, console: &'a ActiveScanout) -> PanelWait<'a> {
        Box::pin(async move {
            if self.generation != Generation::MeteorLake {
                return Err(FsError::Unsupported);
            }
            panel_power_on(self, console).await
        })
    }
}

/// A modeset failure on the panel's crtc disable or enable.
fn panel_modeset_error(_: crate::intel_gpu_modeset::ModesetError) -> FsError {
    crate::intel_gpu_user::io_error()
}

/// The owned display-14 panel's crtc off, after the KMS owner's pre-plane
/// update: `intel_crtc_disable_planes`, then `intel_ddi_disable_dp`'s
/// `intel_edp_backlight_off` (the DPCD backlight off and the PPS gate
/// closed, T9 waited without spinning), then the rest of `hsw_crtc_disable`
/// and the post-plane settle (`XeLpgModeset::panel_off`).
async fn panel_power_off(io: &Physical) -> Result<(), FsError> {
    use crate::intel_gpu_modeset_xelpg::XeLpgModeset;
    use crate::intel_gpu_xelpg::XeLpgPort;
    XeLpgModeset::new(io, XeLpgPort::A)
        .disable_planes()
        .map_err(panel_modeset_error)?;
    crate::intel_dpcd_bl::suspend_complete_for_bar(&io.bar)
        .await
        .map_err(|_| crate::intel_gpu_user::io_error())?;
    XeLpgModeset::new(io, XeLpgPort::A)
        .panel_off()
        .map(|_| ())
        .map_err(panel_modeset_error)
}

/// The panel's crtc on again with `console` scanned out, as the system
/// resume relight does: the DPCD backlight owner powers the panel with its
/// gate closed, the owned modeset runs its full enable at the recorded
/// mode, then the owner relights the backlight after T8. Without a DPCD
/// owner the PPS gate opens after T8 here (`intel_pps_backlight_on`).
async fn panel_power_on(io: &Physical, console: &ActiveScanout) -> Result<(), FsError> {
    use crate::intel_gpu_modeset_xelpg::{panel_off_record, XeLpgModeset};
    use crate::intel_gpu_pm::PmPlatform as _;
    use crate::intel_gpu_xelpg::XeLpgPort;
    let record = panel_off_record().ok_or(FsError::Busy)?;
    let mode = record
        .mode
        .or_else(|| crate::intel_gpu_pm::ProductionPlatform.display_state().0)
        .ok_or_else(crate::intel_gpu_user::io_error)?;
    let aux = crate::intel_dpcd_bl::installed(&io.bar);
    if aux {
        crate::intel_dpcd_bl::prepare_relight_for_bar(&io.bar)
            .map_err(|_| crate::intel_gpu_user::io_error())?;
    }
    let fb = crate::intel_gpu_modeset::Framebuffer {
        phys_addr: u64::from(console.gtt_offset),
        stride_bytes: console.stride_bytes,
        format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
    };
    XeLpgModeset::new(io, XeLpgPort::A)
        .modeset_fixed(&fb, &mode)
        .map_err(panel_modeset_error)?;
    if aux {
        return crate::intel_dpcd_bl::resume_for_bar(&io.bar)
            .map_err(|_| crate::intel_gpu_user::io_error());
    }
    let delays = crate::intel_gpu_edp::panel_delays();
    narf_time::SleepUntil::new(
        narf_time::Deadline::after_ns(u64::from(delays.t8) * 100_000).as_instant(),
    )
    .await;
    crate::intel_gpu_edp::PanelPowerSequencer::with_delays(io, delays)
        .backlight_on()
        .map_err(|_| crate::intel_gpu_user::io_error())
}

/// FBIOBLANK on the Intel console: [`Device::console_dpms`] on the
/// display of `bar`, with the card's KMS master as the refusal.
pub(crate) async fn console_dpms_for_bar(
    bar: &narf_bus::MmioRegion,
    on: bool,
) -> Result<(), FsError> {
    let display = display_for_bar(bar).ok_or(FsError::NoDevice)?;
    let index = display.platform.index;
    display
        .console_dpms(on, || {
            crate::drm_registry::mode_state(index)
                .is_some_and(|card| card.lock().has_master())
        })
        .await
}

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn inherited_fetchers_idle(
    mmio: &impl MmioWindow,
    generation: Generation,
) -> Result<(), FsError> {
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
/// The inventory a KMS owner's fetcher proofs read: a Panther Lake owner is
/// display 30.00, whose `xe2_lpd_display` inventory (FBC A–D, five
/// universal planes) is display 20's.
fn fetcher_generation(platform: &Physical) -> Generation {
    if platform.display30.is_some() {
        Generation::LunarLake
    } else {
        platform.generation
    }
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
    let fbc_count = match generation {
        Generation::MeteorLake => 2,
        // xe2_lpd_display.fbc_mask: FBC A–D.
        Generation::LunarLake => crate::intel_gpu_xe2lpd::DisplayIp::Xe2Lpd.fbc_instances(),
        _ => 1,
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
    // six. ADL-S is display12 with HAS_D12_PLANE_MINIMIZATION. Display 13+
    // (MTL's 14, LNL's 20) has four.
    let count = match generation {
        Generation::MeteorLake | Generation::AlderLake | Generation::LunarLake => 5,
        _ => 7,
    };
    // Display 14: a Pipe B–D primary the MTL external route lit through the
    // Pipe B–D owner scans its own allocation, outside this owner's GEM
    // arena; it is neither this owner's fetcher nor one it could retire.
    // Only that exact surface on that pipe's primary is admitted.
    let external = if generation == Generation::MeteorLake {
        crate::intel_gpu_xelpg_pipes::published_layout().map_or([None; 4], |l| l.surfaces)
    } else {
        [None; 4]
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
                let surface = mmio.read32(0x7019c + pipe * 0x1000);
                let routed = plane == 1
                    && external[pipe as usize].is_some_and(|owned| {
                        owned == surface
                            && !(GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END)
                                .contains(&u64::from(owned))
                    });
                if surface == u32::MAX {
                    return Err(FsError::NoDevice);
                }
                if !routed {
                    return Err(FsError::Unsupported);
                }
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
    /// Display-14 FBC A over a DSM-placed CFB; active only while a KMS GEM
    /// framebuffer is latched, stopped at every session start.
    fbc: Option<crate::intel_gpu_fbc::Fbc>,
    /// No CFB could be placed (or not display 14): never retried.
    fbc_refused: bool,
    /// Display-14 PSR1 on the KMS-owned Pipe-A eDP: enabled after a
    /// latched KMS framebuffer, paused at every session start and re-armed
    /// once the session's frame changes latched; disabled before console
    /// restore, legacy guards and reset recovery.
    psr: Option<crate::intel_gpu_psr::Psr>,
    /// The sink's PSR DPCD, read once.
    psr_sink: Option<crate::intel_gpu_psr::Sink>,
    /// A refusal that holds for the card's lifetime.
    psr_refused: Option<crate::intel_gpu_psr::Refusal>,
    /// Why the last PSR qualification fell back to PSR1 (`None` when it
    /// selected PSR2 or did not reach selective update).
    psr2_refused: Option<crate::intel_gpu_psr::Psr2Refusal>,
    /// The panel's crtc is off ([`Guard::panel_off`]): Pipe A is dark and
    /// holds no display wakeref until [`Guard::panel_on`].
    panel_off: bool,
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
    /// The session's runtime-PM reference (`intel_display_rpm_get`),
    /// released last.
    _rpm: Option<DisplayWakeref>,
}

impl<M: Platform> Drop for Guard<'_, M> {
    /// `intel_psr_resume` at the end of the session: a PSR the session
    /// start paused is re-armed only once every frame change it began has
    /// latched. The DC_off reference and the mutex are still held here.
    fn drop(&mut self) {
        if self.state.psr.as_ref().is_some_and(|psr| !psr.active()) && self.psr_quiescent() {
            self.psr_rearm();
        }
    }
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
    // Panther Lake is owned only as display 30.00 behind the opted-in
    // route, which holds Pipe A for its eDP panel: linear, X-tiled and Tile4
    // primary flips through DPT, the 64x64 cursor, CTM and double-buffered LUTs,
    // and DSB transactions on the console's Pipe A. XR30, FBC and PSR are not offered.
    let display30 = if generation == Generation::PantherLake {
        if !crate::intel_gpu_xe2lpd::route_owns_pipe_a() {
            return;
        }
        let window = crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap);
        let flush = crate::intel_gpu_xe3lpd::wa_15015404425_active(&window);
        if crate::intel_gpu_xe2lpd::DisplayIp::read_all(&crate::intel_gpu_xe3lpd::View::new(
            &window, flush,
        )) != Ok(crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd)
        {
            return;
        }
        Some(Display30 { flush })
    } else {
        None
    };
    let platform = Physical {
        index,
        bar,
        device,
        cap,
        window: crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap),
        generation,
        display30,
        reset_lost: Arc::new(AtomicBool::new(false)),
        recovering: false,
        fbc_carve: Arc::new(crate::intel_gpu_stolen::CarveSlot::new()),
    };
    // Lunar Lake is owned only as display 20.00 (§17 10.5): primary flips
    // on the console's Pipe A, with the display-14 cursor, CTM/LUTs and DSB
    // transactions. XR30, FBC and PSR stay unadvertised and refused.
    if generation == Generation::LunarLake
        && crate::intel_gpu_xe2lpd::DisplayIp::read(&platform)
            != Ok(crate::intel_gpu_xe2lpd::DisplayIp::Xe2Lpd)
    {
        return;
    }
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
    // Wa_14015648006's input: the display-14 watermark code's Pipe-A
    // wm_level_disabled for the watermarks proved programmed.
    if generation == Generation::MeteorLake {
        crate::intel_gpu_xelpg_wm::register_psr_provider();
    }
    // The owned internal Pipe A is lit (the console scans out of it): its
    // pipe DMC is enabled once the program loads (intel_modeset_setup's
    // sanitize of an active pipe). A refused DC exit still records it.
    let _ = crate::intel_gpu_dc_states::pipe_lit_for_bar(&bar, 0);
    if let Some(card) = crate::drm_registry::mode_state(index) {
        let mut card = card.lock();
        card.native_atomic = true;
        card.intel_display = true;
        if matches!(
            generation,
            Generation::MeteorLake | Generation::LunarLake | Generation::PantherLake
        ) {
            if let Some(crtc) = card.crtcs.first().map(|c| c.id) {
                card.intel_ctm = true;
                if card.crtc_color(crtc).is_none() {
                    card.crtc_color.push(crate::drm::card::CrtcColor::new(crtc));
                }
            }
        }
    }
    // Seed the Pipe-A VRR state for CRTC 1 from the live console
    // mode. The mode is the firmware scanout's (the best available
    // before a real modeset); the sink range is NOT seeded here —
    // the old code hardcoded `VrrRange { 48, 60 }` and computed
    // timings from it, so VRR ran once at install from a range no
    // sink had advertised and the timings went stale on every later
    // modeset. The range stays `None` (and the timings with it)
    // until DP/eDP discovery publishes it (`probe_sink` /
    // `activate_on_pipe`), and every modeset recomputes the timings
    // from the committed mode + that range instead.
    let (width, height) = (console.width as u16, console.height as u16);
    let default_mode = crate::intel_gpu_modeset::Mode {
        pixel_clock_khz: (u32::from(width) * u32::from(height) * 60) / 1000,
        h_active: width,
        h_total: width + 160,
        h_sync_start: width + 48,
        h_sync_end: width + 80,
        v_active: height,
        v_total: height + 40,
        v_sync_start: height + 3,
        v_sync_end: height + 9,
        h_sync_positive: false,
        v_sync_positive: false,
    };
    let ip = crate::intel_gpu_vrr::DisplayVrrIp::from_generation(generation);
    crate::intel_gpu_vrr::VRR_STATE.set_mode(1, Some(default_mode));
    crate::intel_gpu_vrr::VRR_STATE.set_range(1, None);
    crate::intel_gpu_vrr::VRR_STATE.set_timings(1, None);
    if let Some(cmrr_timings) = crate::intel_gpu_vrr::CmrrTimings::compute(
        &default_mode,
        crate::intel_gpu_vrr::CmrrRate::Fps59_940,
        ip,
    ) {
        crate::intel_gpu_vrr::VRR_STATE
            .set_cmrr_rate(1, Some(crate::intel_gpu_vrr::CmrrRate::Fps59_940));
        crate::intel_gpu_vrr::VRR_STATE.set_cmrr_timings(1, Some(cmrr_timings));
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
    if !matches!(
        display.generation,
        Generation::MeteorLake | Generation::LunarLake | Generation::PantherLake
    ) || display.platform.published_epoch() != Some(epoch)
    {
        return true;
    }
    let Some(state) = display.state.try_lock() else {
        return false;
    };
    if state.panel_off {
        // Nothing scans out: the formats are qualified again once lit.
        return true;
    }
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
/// Retire an owned Meteor Lake external route, its hotplug sources and its
/// publication for this BAR (`intel_gpu::retire_mtl_external`). Other
/// generations return before any register access.
fn retire_mtl_external(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
    crate::intel_gpu::retire_mtl_external(bar)
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
                fbc: None,
                fbc_refused: false,
                psr: None,
                psr_sink: None,
                psr_refused: None,
                psr2_refused: None,
                panel_off: false,
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
        // An owned PSR is disabled (source, then sink) through the same
        // loss-tolerant view before recovery's own PSR handoff runs.
        if state.psr.is_some() {
            match self.platform.fbc_recovery_view() {
                Some(view) => psr_disable(&mut state, &view, None),
                None => psr_disable(&mut state, &self.platform, None),
            }
        }
        // An owned FBC must stop before recovery's fetcher inventory, which
        // refuses any enabled FBC; the loss-blocked window cannot reach it.
        if let Some(fbc) = state.fbc.as_mut() {
            match self.platform.fbc_recovery_view() {
                Some(view) => fbc.disable(&view),
                None => fbc.disable(&self.platform),
            }
        }
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
        let pat = crate::intel_gpu_scanout_io::display_pte_ip(self.generation, fresh.display_ip())
            .map_or(0, |(_, pat)| pat);
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
        self.session_for(false).await
    }
    /// A session for one primary present: an active PSR2 selective update
    /// keeps running, and the present programs the commit's selective
    /// fetch ([`Guard::present_damaged`]). PSR1, and PSR2 not active, are
    /// paused as by [`Device::session`].
    pub(crate) async fn selective_session(&self) -> Result<Guard<'_, M>, FsError> {
        self.session_for(true).await
    }
    async fn session_for(&self, selective: bool) -> Result<Guard<'_, M>, FsError> {
        // intel_atomic_commit's intel_display_rpm_get: a runtime-suspended
        // function (a dark panel let it park) resumes before the session
        // touches a register, and stays active until the session ends.
        let rpm = self.platform.display_rpm().await?;
        let mut state = self.state.lock().await;
        if state.blocked || state.failed || self.platform.reset_lost() {
            return Err(FsError::NoDevice);
        }
        let _power = self.platform.display_power()?;
        // intel_fbc_invalidate: compression stops before this session
        // touches the plane, takeover inventory or frontbuffer.
        if let Some(fbc) = state.fbc.as_mut() {
            fbc.invalidate(&self.platform);
        }
        let mut guard = Guard {
            device: self,
            state,
            _power,
            _rpm: rpm,
        };
        // intel_psr_pause: PSR exits and reaches idle before this session
        // can change any frame (flip, DIRTYFB, cursor, color/DSB, console),
        // unless a selective update keeps running through a present.
        if !(selective
            && guard
                .state
                .psr
                .is_some_and(|psr| psr.selective() && psr.active()))
        {
            guard.psr_pause().await;
        }
        Ok(guard)
    }
    pub(crate) async fn quiesce(&self) -> Result<(), FsError> {
        let state = self.state.lock().await;
        let _power = self.platform.display_power()?;
        let mut guard = Guard {
            device: self,
            state,
            _power,
            _rpm: None,
        };
        guard.restore_console().await?;
        self.platform.color_restored();
        guard.state.blocked = true;
        Ok(())
    }
}
impl<M: Platform> Device<M> {
    /// `drm_client_modeset_dpms` for the kernel console (Linux b90c984d
    /// `drm_client_modeset.c`, reached from `drm_fb_helper_blank`): `on` is
    /// `mode == DRM_MODE_DPMS_ON`. With a KMS master (`master`) the console
    /// does not own the crtc and nothing changes (`Busy`, as
    /// `drm_master_internal_acquire` refuses). Otherwise the console's crtc
    /// goes off (the console restored first, so no KMS surface remains) or
    /// back on.
    pub(crate) async fn console_dpms(
        &self,
        on: bool,
        master: impl Fn() -> bool,
    ) -> Result<(), FsError> {
        let mut guard = self.session().await?;
        if master() {
            return Err(FsError::Busy);
        }
        if on {
            guard.panel_on().await
        } else {
            if !guard.panel_dark() {
                guard.restore_console().await?;
            }
            guard.panel_off().await
        }
    }
}

impl<M: Platform> Device<M> {
    /// Stop-only external owner keeps all existing presenters/color/DMA in
    /// place. It cannot arm or adopt them; fresh authority is checked by its IO.
    pub(crate) fn legacy_drain(&self) -> Result<LegacyGuard<'_, M>, FsError> {
        let mut state = self.state.try_lock().ok_or(FsError::Busy)?;
        let _power = self.platform.display_power()?;
        psr_disable(&mut state, &self.platform, None);
        if let Some(fbc) = state.fbc.as_mut() {
            fbc.disable(&self.platform);
        }
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

/// `PIPE_FRMCOUNT_G4X(PIPE_A)`.
const FRAME_A: u64 = 0x70040;
/// One Pipe-A frame boundary after the sample `start`: the double-buffered
/// registers armed before it have latched (`intel_crtc_wait_for_next_vblank`
/// bounded at 100 ms, the live repartition's budget). `false` on timeout or
/// lost access.
fn wait_frame_after(platform: &impl Platform, start: u32) -> bool {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let now = platform.read32(FRAME_A);
            lost = now == u32::MAX || !platform.access_ok();
            lost || now != start
        },
        narf_time::Deadline::after_ms(100),
    );
    done && !lost
}

/// What the MTL external pass did around one hotplug event, for the
/// post-update.
#[derive(Debug)]
struct Bracket {
    /// FBC was deactivated by the pre-update (it was active).
    fbc_was_active: bool,
}

/// The MTL external pass's hold on the panel's KMS owner (display 14).
///
/// An external output added or removed beside the lit panel repartitions
/// the resources Pipe A runs on (its DDB and watermarks, MBUS, DBUF, CDCLK
/// and PM demand). Linux adds Pipe A to that commit
/// (`skl_ddb_add_affected_pipes`), so the commit is serialized with the
/// panel's own updates and runs its pre/post plane updates for Pipe A. The
/// pass does the same: it holds this owner's mutex (no flip, cursor, color
/// or DSB arm can race the repartition) and, around the event,
/// [`ExternalPass::pre_update`] / [`ExternalPass::post_update`] stand in for
/// `intel_fbc_pre_update`, `intel_psr_pre_plane_update` with the pipe
/// update's PSR exit, and `intel_fbc_post_update` /
/// `intel_psr_post_plane_update`. Unlike [`Device::legacy_drain`] it never
/// blocks the owner: the panel's proofs are multi-pipe aware
/// ([`crate::intel_gpu_display_resources::Profile`]).
#[derive(Debug)]
pub(crate) struct ExternalPass<'a, M: Platform> {
    guard: Guard<'a, M>,
    bracket: Option<Bracket>,
}

impl<M: Platform> Device<M> {
    /// Take the panel's KMS owner for one MTL external pass. Never waits
    /// on another task: `Busy` while a KMS transaction holds the owner or a
    /// primary frame change it began is still unlatched (the pass is then
    /// retried later; its hotplug event stays queued). An in-flight DSB
    /// stream on the panel (a cursor or color update whose future was
    /// dropped) is waited for, bounded, before the pass may repartition:
    /// Linux's commit waits for the previous commit's DSB
    /// (`intel_atomic_dsb_wait_commit`) before a new one touches the pipe.
    /// The cursor/color bookkeeping of that stream stays for the owner's
    /// next call; the repartition preserves every register it verifies.
    pub(crate) fn external_pass(&self) -> Result<ExternalPass<'_, M>, FsError> {
        let state = self.state.try_lock().ok_or(FsError::Busy)?;
        let _power = self.platform.display_power()?;
        let mut guard = Guard {
            device: self,
            state,
            _power,
            _rpm: None,
        };
        guard.idle_dsb()?;
        let state = &guard.state;
        if state.pending.is_some()
            || state.joint.is_some()
            || state.presenter.as_ref().is_some_and(|p| p.pending())
            || state
                .primary_resources
                .as_ref()
                .is_some_and(|p| p.pending())
        {
            return Err(FsError::Busy);
        }
        Ok(ExternalPass {
            guard,
            bracket: None,
        })
    }
}

impl<M: Platform> Guard<'_, M> {
    /// Retire an armed DSB stream synchronously (bounded at 100 ms; a
    /// stream completes at the vblank after its arm). A DSB error or a
    /// timeout fails the owner exactly as its own completion poll would.
    fn idle_dsb(&mut self) -> Result<(), FsError> {
        let platform = &self.device.platform;
        let Some(dsb) = self.state.dsb.as_mut() else {
            return Ok(());
        };
        if !dsb.armed() {
            return Ok(());
        }
        let mut result = Ok(false);
        narf_scheduler::responsive_spin_until(
            || {
                result = dsb.poll(platform.now());
                !matches!(result, Ok(false))
            },
            narf_time::Deadline::after_ms(100),
        );
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(FsError::Busy),
            Err(error) => {
                self.state.failed = true;
                Err(error)
            }
        }
    }
}

impl<M: Platform> ExternalPass<'_, M> {
    /// Before a hotplug event may repartition Pipe A's resources.
    ///
    /// - `intel_fbc_pre_update`: FBC is deactivated ("update pending"). The
    ///   live transaction requires FBC off, so this always takes the branch
    ///   Linux takes when `intel_fbc_can_flip_nuke` fails; Display WA #1198
    ///   then waits one Pipe-A vblank before the plane update when FBC was
    ///   active.
    /// - `intel_psr_pre_plane_update` for a Pipe A without a modeset: PSR
    ///   stays enabled; Wa_14015648006 is set when Pipe A's
    ///   `wm_level_disabled` is true (it is per crtc and the same in every
    ///   layout). The pipe update's exit and idle wait
    ///   (`intel_psr_wait_for_idle_locked`) follow, bounded at
    ///   [`crate::intel_gpu_psr::PSR_EXIT_TIMEOUT_MS`]; a latched error or a
    ///   failed exit disables PSR.
    pub(crate) fn pre_update(&mut self) {
        if self.bracket.is_some() {
            return;
        }
        let guard = &mut self.guard;
        let platform = &guard.device.platform;
        let fbc_was_active = guard.state.fbc.as_ref().is_some_and(|f| f.active());
        if let Some(fbc) = guard.state.fbc.as_mut() {
            fbc.deactivate(platform);
        }
        let start = platform.read32(FRAME_A);
        if guard.state.psr.is_some() {
            if crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled() == Some(true) {
                guard.psr_wm_update(true);
            }
            let platform = &guard.device.platform;
            let paused = guard.state.psr.as_mut().map(|psr| {
                psr.pause(platform).and_then(|()| {
                    psr.wait_idle(platform, crate::intel_gpu_psr::PSR_EXIT_TIMEOUT_MS)
                })
            });
            if let Some(Err(refusal)) = paused {
                psr_disable(&mut guard.state, platform, Some(refusal));
            }
        }
        if fbc_was_active && start != u32::MAX {
            let _ = wait_frame_after(&guard.device.platform, start);
        }
        self.bracket = Some(Bracket { fbc_was_active });
    }

    /// After the hotplug event (a repartition, a refusal or an undone
    /// failure). Post-plane updates run after the commit's flip_done in
    /// `intel_atomic_commit_tail`, so one Pipe-A frame boundary is waited
    /// for first: whatever the repartition armed on Pipe A has latched.
    /// Pipe A's resources are then proved in whatever layout now holds
    /// (publishing its `wm_level_disabled`). Only a proved layout takes
    /// FBC and PSR back: `intel_fbc_post_update` re-activates FBC on the
    /// latched KMS framebuffer (re-evaluated; the CFB carve is unchanged),
    /// and `intel_psr_post_plane_update` clears Wa_14015648006 when
    /// `wm_level_disabled` is false while PSR re-arms from idle when the
    /// pass ends. An unproved layout disables PSR (its next qualification
    /// re-proves the watermarks) and leaves FBC off until the next latch,
    /// so neither runs on stale DDB/WM.
    pub(crate) fn post_update(&mut self) {
        let Some(bracket) = self.bracket.take() else {
            return;
        };
        let guard = &mut self.guard;
        let platform = &guard.device.platform;
        let start = platform.read32(FRAME_A);
        let latched = start != u32::MAX && wait_frame_after(platform, start);
        let proved = latched
            && match (&guard.state.primary_resources, platform.psr_timing()) {
                (Some(primary), _) => primary.check_current(platform).is_ok(),
                (None, Some(timing)) => {
                    crate::intel_gpu_display_resources::Profile::capture_timing(platform, timing)
                        .is_ok()
                }
                (None, None) => false,
            };
        if !proved {
            psr_disable(&mut guard.state, platform, None);
            return;
        }
        if guard.state.psr.is_some()
            && crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled() == Some(false)
        {
            guard.psr_wm_update(false);
        }
        if bracket.fbc_was_active && guard.state.current.is_some() {
            let geometry = guard.console_geometry();
            guard.fbc_after_latch(geometry);
        }
    }
}

impl<M: Platform> Drop for ExternalPass<'_, M> {
    /// A pass that ran the pre-update always runs the post-update; the
    /// guard's own drop then re-arms a paused PSR from idle.
    fn drop(&mut self) {
        self.post_update();
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
        if self.state.failed || self.state.blocked || self.device.platform.reset_lost() {
            return Err(FsError::NoDevice);
        }
        // A dark panel has no console scanout to prove: its retained owners
        // re-prove themselves after the panel is on again.
        if self.state.panel_off {
            return Ok(());
        }
        if !self.device.platform.console_access_ok() {
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
                    let mut completed_primary = false;
                    if let Some(resources) = state.primary_resources.as_mut() {
                        let result = if resources.pending() {
                            completed_primary = true;
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
                    if completed_primary {
                        self.psr_wm_post_update();
                    }
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
        let pat = crate::intel_gpu_scanout_io::display_pte_ip(
            self.device.generation,
            self.device.platform.display_ip(),
        )
        .map_or(0, |(_, pat)| pat);
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
        self.present_damaged(object, geometry, &crate::drm::fb_cmd::Damage::Full)
            .await
    }
    /// [`Guard::present`] for a commit whose primary-plane damage is
    /// `damage` (FB_DAMAGE_CLIPS or DIRTYFB clips). An active PSR2 runs a
    /// selective update: the commit's selective fetch is programmed around
    /// the arm ([`Guard::psr_su_prepare`]).
    pub(crate) async fn present_damaged(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
        damage: &crate::drm::fb_cmd::Damage,
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
        let selective = self.psr_su_prepare(damage).await;
        let id = self.prepare_surface(object.clone(), geometry, Default::default())?;
        let ticket = self.ticket()?;
        // Record the new owner before arming. Cancellation never unpins it.
        self.state.pending = Some((object, id));
        if let (Some(sf), Some(psr)) = (&selective, self.state.psr.as_mut()) {
            psr.program_sel_fetch_arm(&self.device.platform, sf);
        }
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
        // The cursor's arm follows the primary's in the same commit.
        if let (Some(sf), Some(psr)) = (&selective, self.state.psr.as_mut()) {
            psr.program_sel_fetch_cursor(&self.device.platform, sf);
        }
        crate::intel_gpu_vrr::on_plane_flip(1, &self.device.platform);
        let stamp = self
            .finish_pending()
            .await?
            .ok_or_else(crate::intel_gpu_user::io_error)?;
        // intel_psr_post_plane_update after the latch: enable once (PSR
        // wins over FBC on display 14; activation waits for the session
        // end), then __intel_fbc_flush (flips and DIRTYFB re-presents).
        self.psr_after_latch();
        self.fbc_after_latch(geometry);
        Ok(stamp)
    }
    /// Display-14 PSR1 after a latched KMS framebuffer. Enabling disables
    /// FBC first: Wa_14016291713 refuses FBC with PSR1 and this driver has
    /// no stepping readout, so PSR wins (intel_fbc_check_plane runs against
    /// a state whose has_psr was computed first). The Guard's drop
    /// activates it, so later frame changes in this session still run with
    /// PSR exited.
    fn psr_after_latch(&mut self) {
        if self.device.generation != Generation::MeteorLake
            || self.state.current.is_none()
            || self.state.psr.is_some()
            || self.state.psr_refused.is_some()
        {
            return;
        }
        let refusal = match self.psr_qualify() {
            Ok((config, su)) => {
                if let Some(fbc) = self.state.fbc.as_mut() {
                    fbc.disable(&self.device.platform);
                }
                let platform = &self.device.platform;
                let enabled = match su {
                    // The commit that qualified PSR2 damaged the whole plane.
                    Some(su) => self.psr_su_facts().and_then(|(scaled, cursor)| {
                        let src = crate::drm::fb_cmd::Rect::new(
                            0,
                            0,
                            i32::from(su.width),
                            i32::from(su.height),
                        );
                        crate::intel_gpu_psr::Psr::enable_su(
                            platform,
                            &mut PsrAux(platform),
                            config,
                            su,
                            &crate::intel_gpu_psr::SuCommit {
                                damage: &crate::drm::fb_cmd::Damage::Full,
                                old_src: src,
                                src,
                                pipe_supported: !scaled,
                                cursor,
                            },
                        )
                    }),
                    None => {
                        crate::intel_gpu_psr::Psr::enable(platform, &mut PsrAux(platform), config)
                    }
                };
                match enabled {
                    Ok(psr) => {
                        self.state.psr = Some(psr);
                        return;
                    }
                    Err(refusal) => refusal,
                }
            }
            Err(refusal) => refusal,
        };
        if refusal.latched() {
            self.state.psr_refused = Some(refusal);
        }
    }
    /// `intel_psr_compute_config` against the live fixed timing, the VBT,
    /// the (cached) sink capability and the `wm_level_disabled` of the
    /// Pipe-A watermarks proved programmed just now; then
    /// `intel_sel_update_config_valid`, whose refusal (recorded in
    /// `psr2_refused`) falls back to PSR1.
    #[allow(clippy::type_complexity)]
    fn psr_qualify(
        &mut self,
    ) -> Result<
        (
            crate::intel_gpu_psr::Psr1,
            Option<crate::intel_gpu_psr::Psr2>,
        ),
        crate::intel_gpu_psr::Refusal,
    > {
        use crate::intel_gpu_psr::{
            compute_psr1, compute_psr2, psr2_source, Psr2Refusal, Refusal, Sink,
            DRM_MODE_FLAG_INTERLACE,
        };
        let platform = &self.device.platform;
        let timing = platform.psr_timing().ok_or(Refusal::NoTiming)?;
        // psr_global_enabled comes first: no sink conversation for a panel
        // the VBT does not enable.
        let vbt = platform.psr_vbt();
        let panel = vbt.enabled()?;
        if timing.flags & DRM_MODE_FLAG_INTERLACE != 0 {
            return Err(Refusal::Interlaced);
        }
        // The card's mode must be the one transcoder A is running
        // (TRANS_HTOTAL / TRANS_VTOTAL, active and total minus one).
        let console = self.console_geometry();
        let packed = |total: u16, active: u16| {
            (u32::from(total).wrapping_sub(1) << 16) | u32::from(active).wrapping_sub(1)
        };
        if (u32::from(timing.width), u32::from(timing.height)) != (console.width, console.height)
            || timing.clock == 0
            || platform.read32(0x60000) != packed(timing.htotal, timing.width)
            || platform.read32(0x6000c) != packed(timing.vtotal, timing.height)
        {
            return Err(Refusal::NoTiming);
        }
        let sink = match self.state.psr_sink {
            Some(sink) => sink,
            None => {
                let sink = Sink::read(&mut PsrAux(platform))?;
                self.state.psr_sink = Some(sink);
                sink
            }
        };
        // Prove the programmed Pipe-A watermarks now (the retained primary
        // owner, else the fixed console profile); the proof publishes their
        // wm_level_disabled, or "unknown" when it fails.
        match &self.state.primary_resources {
            Some(primary) => {
                let _ = primary.check_current(platform);
            }
            None => {
                let _ =
                    crate::intel_gpu_display_resources::Profile::capture_timing(platform, timing);
            }
        }
        let config = compute_psr1(&sink, &timing, &vbt, platform.psr_wm_level_disabled())?;
        // has_sel_update: a sink without SU support needs no source facts.
        let su = if sink.su_support() {
            psr2_source(
                platform,
                &mut PsrAux(platform),
                &sink,
                platform.psr_pci_ids(),
            )
            .and_then(|source| compute_psr2(&sink, &timing, &panel, &source))
        } else {
            Err(Psr2Refusal::NoSinkSu)
        };
        self.state.psr2_refused = su.err();
        Ok((config, su.ok()))
    }
    /// The live pipe facts a selective-fetch commit needs: whether a pipe
    /// or plane scaler is engaged, and the visible cursor.
    #[allow(clippy::type_complexity)]
    fn psr_su_facts(
        &self,
    ) -> Result<(bool, Option<crate::intel_gpu_psr::CursorPlane>), crate::intel_gpu_psr::Refusal>
    {
        let platform = &self.device.platform;
        Ok((
            crate::intel_gpu_psr::pipe_scaled(platform)?,
            crate::intel_gpu_psr::CursorPlane::read(platform)?,
        ))
    }
    /// `intel_psr_pause` and `intel_psr_wait_exit_locked` within
    /// [`crate::intel_gpu_psr::PSR_EXIT_TIMEOUT_MS`] for this PSR's mode. A
    /// latched error or a failed exit disables PSR instead.
    async fn psr_pause(&mut self) {
        use crate::intel_gpu_psr::{Refusal, PSR_EXIT_TIMEOUT_MS};
        let device = self.device;
        let platform = &device.platform;
        match self.state.psr.as_mut().map(|psr| psr.pause(platform)) {
            None => return,
            Some(Err(refusal)) => {
                psr_disable(&mut self.state, platform, Some(refusal));
                return;
            }
            Some(Ok(())) => {}
        }
        let Some(psr) = self.state.psr else {
            return;
        };
        let deadline = platform
            .now()
            .saturating_add(PSR_EXIT_TIMEOUT_MS * 1_000_000);
        let exited = loop {
            match psr.idle(platform) {
                Ok(true) => break Ok(()),
                Ok(false) if platform.now() < deadline => platform.tick().await,
                Ok(false) => break Err(Refusal::ExitTimeout),
                Err(refusal) => break Err(refusal),
            }
        };
        if let Err(refusal) = exited {
            psr_disable(&mut self.state, platform, Some(refusal));
        }
    }
    /// The PSR half of a primary commit before its arm, for an active PSR2
    /// selective update (`intel_psr2_sel_fetch_update`, then the pipe
    /// update): compute the SU area from `damage` and the live cursor,
    /// write the primary's no-arm selective-fetch registers, raise the
    /// frame-change event and wait (bounded at `PSR_IDLE_TIMEOUT_MS`) for
    /// PSR2 to leave deep sleep. The caller writes the arm half around the
    /// plane arm. Linux proceeds after a timed-out wait; here PSR2 also
    /// exits then (the guard's drop re-arms it), because no vblank
    /// interrupt can wake it. Anything in flight on the pipe (DSB, cursor
    /// or color) exits PSR as every other session does. A latched error or
    /// a register that reads all-ones disables PSR. `None` when no
    /// selective update runs.
    async fn psr_su_prepare(
        &mut self,
        damage: &crate::drm::fb_cmd::Damage,
    ) -> Option<crate::intel_gpu_psr::SelFetch> {
        use crate::intel_gpu_psr::{frame_change_event, Psr, SuCommit, PSR_IDLE_TIMEOUT_MS};
        let device = self.device;
        let platform = &device.platform;
        let psr = self.state.psr?;
        if !psr.active() {
            return None;
        }
        if !psr.selective() {
            self.psr_pause().await;
            return None;
        }
        if let Err(refusal) = Psr::error(platform) {
            psr_disable(&mut self.state, platform, Some(refusal));
            return None;
        }
        let state = &self.state;
        if state.joint.is_some()
            || state.dsb.as_ref().is_some_and(|d| d.armed())
            || state.cursor.as_ref().is_some_and(|c| c.pending())
            || state.color.as_ref().is_some_and(|c| c.pending())
        {
            self.psr_pause().await;
            return None;
        }
        let (scaled, cursor) = match self.psr_su_facts() {
            Ok(facts) => facts,
            Err(refusal) => {
                psr_disable(&mut self.state, platform, Some(refusal));
                return None;
            }
        };
        let geometry = self.console_geometry();
        let src =
            crate::drm::fb_cmd::Rect::new(0, 0, geometry.width as i32, geometry.height as i32);
        let sf = psr.sel_fetch(&SuCommit {
            damage,
            old_src: src,
            src,
            pipe_supported: !scaled,
            cursor,
        })?;
        psr.program_sel_fetch_noarm(platform, &sf);
        frame_change_event(platform);
        let deadline = platform
            .now()
            .saturating_add(PSR_IDLE_TIMEOUT_MS * 1_000_000);
        loop {
            match psr.ready_for_update(platform) {
                Ok(true) => break,
                Ok(false) if platform.now() < deadline => platform.tick().await,
                Ok(false) => {
                    self.psr_pause().await;
                    break;
                }
                Err(refusal) => {
                    psr_disable(&mut self.state, platform, Some(refusal));
                    return None;
                }
            }
        }
        Some(sf)
    }
    /// `intel_psr_pre_plane_update`'s Wa_14015648006 half: before a staged
    /// primary image whose `wm_level_disabled` is true can latch, an
    /// enabled PSR gets `LATENCY_REPORTING_REMOVED`.
    fn psr_wm_pre_update(&mut self) {
        let target = self.state.primary_resources.as_ref().and_then(|primary| {
            primary
                .pending_tile4()
                .map(|tile4| primary.wm_level_disabled(tile4))
        });
        if target == Some(true) {
            self.psr_wm_update(true);
        }
    }
    /// `intel_psr_post_plane_update`'s Wa_14015648006 half: once the
    /// programmed image's `wm_level_disabled` is false, an enabled PSR
    /// drops `LATENCY_REPORTING_REMOVED`.
    fn psr_wm_post_update(&mut self) {
        let current = self
            .state
            .primary_resources
            .as_ref()
            .and_then(|primary| primary.current_wm_level_disabled());
        if current == Some(false) {
            self.psr_wm_update(false);
        }
    }
    fn psr_wm_update(&mut self, wm_level_disabled: bool) {
        let platform = &self.device.platform;
        let Some(psr) = self.state.psr.as_mut() else {
            return;
        };
        if let Err(refusal) = psr.wm_optimization_wa(platform, wm_level_disabled) {
            psr_disable(&mut self.state, platform, Some(refusal));
        }
    }
    /// `intel_psr_resume`: re-activate a paused PSR from idle; an error
    /// disables it.
    fn psr_rearm(&mut self) {
        let Some(psr) = self.state.psr.as_mut() else {
            return;
        };
        if let Err(refusal) = psr.resume(&self.device.platform) {
            psr_disable(&mut self.state, &self.device.platform, Some(refusal));
        }
    }
    /// Every frame change this session started has latched, and the
    /// KMS-owned framebuffer is on screen.
    fn psr_quiescent(&self) -> bool {
        let state = &self.state;
        !state.failed
            && !state.blocked
            && state.current.is_some()
            && state.pending.is_none()
            && state.joint.is_none()
            && !state.color_unpublished
            && !state.mixed_unpublished
            && !state.dsb.as_ref().is_some_and(|d| d.armed())
            && !state.cursor.as_ref().is_some_and(|c| c.pending())
            && !state.color.as_ref().is_some_and(|c| c.pending())
            && !self.device.platform.reset_lost()
            && self.device.platform.console_access_ok()
    }
    /// Display-14 FBC on the latched KMS framebuffer: once the off-path
    /// carve has placed the CFB, nuke or (re)activate; any ineligible
    /// plane disables.
    fn fbc_after_latch(&mut self, geometry: Geometry) {
        use crate::intel_gpu_fbc::{cfb_size, check_plane, min_limit, override_stride, Fbc};
        // has_psr (enabled, even while paused) refuses FBC: PSR wins, and
        // has_sel_update refuses it first ("Selective update enabled").
        let psr = self.state.psr.is_some();
        let selective_update = self.state.psr.is_some_and(|p| p.selective());
        let plane = crate::intel_gpu_fbc::Plane {
            kms_owned: self.state.current.is_some(),
            format: if self.state.xr30_timing.is_some() || self.state.xr30_epoch.is_some() {
                crate::intel_gpu_fbc::Format::Other
            } else {
                crate::intel_gpu_fbc::Format::Xrgb8888
            },
            width: geometry.width,
            height: geometry.height,
            x: 0,
            y: 0,
            stride_bytes: geometry.pitch,
            per_pixel_alpha: false,
            rotated_90: false,
            interlaced: false,
            psr1: psr,
            selective_update,
        };
        if self.state.fbc.is_none() && !self.state.fbc_refused && check_plane(&plane).is_ok() {
            // Only polled: the carve and its GGTT survey run off this path,
            // and FBC stays off until a later latch finds them finished.
            let size = cfb_size(plane.format, plane.width, plane.height, plane.stride_bytes);
            match self
                .device
                .platform
                .fbc_carve(size, min_limit(plane.format))
            {
                Poll::Ready(Some((offset, bytes, limit))) => {
                    self.state.fbc = Some(Fbc::new(
                        offset,
                        bytes,
                        limit,
                        override_stride(plane.format, plane.width, plane.stride_bytes),
                    ))
                }
                Poll::Ready(None) => self.state.fbc_refused = true,
                Poll::Pending => {}
            }
        }
        if let Some(fbc) = self.state.fbc.as_mut() {
            let _ = fbc.flush(&self.device.platform, &plane);
        }
    }
    /// Whether the panel's crtc is off.
    pub(crate) fn panel_dark(&self) -> bool {
        self.state.panel_off
    }
    #[cfg(any(test, feature = "kernel-test"))]
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn psr(&self) -> Option<crate::intel_gpu_psr::Psr> {
        self.state.psr
    }
    /// The panel's crtc off (display 14): `intel_atomic_commit_tail` for
    /// the crtc going inactive. The caller has restored the console, so no
    /// client surface, cursor, colour or DSB stream remains; a frame change
    /// still unlatched refuses `Busy` before anything is touched. The
    /// pre-plane update disables PSR (`intel_psr_pre_plane_update` for a
    /// modeset) and FBC (`intel_fbc_pre_update`, then `intel_fbc_disable`),
    /// then the platform runs the crtc disable. Idempotent.
    pub(crate) async fn panel_off(&mut self) -> Result<(), FsError> {
        if self.state.panel_off {
            return Ok(());
        }
        if self.state.failed || self.state.blocked || self.device.platform.reset_lost() {
            return Err(FsError::NoDevice);
        }
        let state = &self.state;
        if state.pending.is_some()
            || state.joint.is_some()
            || state.presenter.is_some()
            || state.color_unpublished
            || state.mixed_unpublished
            || state.dsb.as_ref().is_some_and(|d| d.armed())
            || state
                .cursor
                .as_ref()
                .is_some_and(|c| c.active() || c.pending())
            || state.color.as_ref().is_some_and(|c| c.pending())
            || state
                .primary_resources
                .as_ref()
                .is_some_and(|p| p.pending())
        {
            return Err(FsError::Busy);
        }
        psr_disable(&mut self.state, &self.device.platform, None);
        if let Some(fbc) = self.state.fbc.as_mut() {
            fbc.disable(&self.device.platform);
        }
        self.device.platform.panel_off().await?;
        self.state.panel_off = true;
        Ok(())
    }
    /// The panel's crtc on again (the owned modeset at the panel's mode
    /// with the console surface). Idempotent while the panel is lit.
    pub(crate) async fn panel_on(&mut self) -> Result<(), FsError> {
        if !self.state.panel_off {
            return Ok(());
        }
        if self.state.failed || self.state.blocked || self.device.platform.reset_lost() {
            return Err(FsError::NoDevice);
        }
        let console = self.state.console.clone();
        self.device.platform.panel_on(&console).await?;
        self.state.panel_off = false;
        Ok(())
    }
    pub(crate) async fn restore_console(&mut self) -> Result<(), FsError> {
        // Console reclaim: PSR (source, then sink) and FBC are fully
        // disabled before the console framebuffer is scanned out again.
        psr_disable(&mut self.state, &self.device.platform, None);
        if let Some(fbc) = self.state.fbc.as_mut() {
            fbc.disable(&self.device.platform);
        }
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
        // The console framebuffer is never self-refreshed: PSR (source,
        // then sink) is disabled before it is scanned out again.
        psr_disable(&mut self.state, &self.device.platform, None);
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
            Generation::MeteorLake
                | Generation::LunarLake
                | Generation::PantherLake
                | Generation::TigerLake
                | Generation::AlderLake
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
            if !matches!(
                self.device.generation,
                Generation::MeteorLake | Generation::LunarLake | Generation::PantherLake
            ) {
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
                crate::intel_gpu_cursor::Owner::new_for(
                    self.device.platform.clone(),
                    self.device.bar_len,
                    timing,
                    self.device.generation,
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
                    gen12_display13(&self.device.platform),
                )
            } else {
                crate::intel_gpu_dsb::Owner::reserve_for(
                    self.device.platform.clone(),
                    self.device.bar_len,
                    self.device.generation,
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
                        self.psr_wm_post_update();
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
            let ip = tiled_profile(&self.device.platform, geometry, timing, view.layout)?;
            if view.layout == crate::intel_gpu_scanout::Layout::Tile4
                && self.state.primary_resources.is_none()
            {
                // Prove target WM/min-DDB fit before any new GEM mapping.
                crate::intel_gpu_display_resources::Primary::capture_ip(
                    &self.device.platform,
                    timing,
                    ip.ok_or(FsError::Unsupported)?,
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
        if !matches!(
            self.device.generation,
            Generation::MeteorLake | Generation::LunarLake | Generation::PantherLake
        ) && (self.device.platform.gen12_family().is_none()
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
                            gen12_display13(&self.device.platform),
                        )
                    } else {
                        crate::intel_gpu_dsb::Owner::reserve_for(
                            self.device.platform.clone(),
                            self.device.bar_len,
                            self.device.generation,
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
                            Some(crate::intel_gpu_display_resources::Primary::capture_ip(
                                &self.device.platform,
                                timing,
                                resource_ip(self.device.generation),
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
                    self.psr_wm_pre_update();
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
                // The current image stays programmed: undo a pre-update.
                self.psr_wm_post_update();
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
        if primary.is_some() {
            crate::intel_gpu_vrr::on_plane_flip(1, &self.device.platform);
        }
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
