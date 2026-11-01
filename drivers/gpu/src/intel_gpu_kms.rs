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

/// The production implementation retains PCI authority and a permanent UC
/// BAR. Tests implement the same platform boundary with native register models.
pub(crate) trait Platform:
    DisplayAccess + Clone + core::fmt::Debug + Send + Sync + 'static
{
    fn takeover(&self) -> Result<(), FsError>;
    fn color_takeover(&self) -> Result<(), FsError> {
        self.takeover()
    }
    fn color_restored(&self) {}
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
    fn recovery_platform(&self, owned_dsb: bool) -> Result<Self, FsError>;
    fn recovery_complete(&self);
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
impl Platform for Physical {
    fn takeover(&self) -> Result<(), FsError> {
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
        inherited_fetchers_idle(self, self.generation)?;
        if crate::intel_gpu::with_controller(|gpu| gpu.gtt_mmadr.phys) != Some(self.bar.phys) {
            return Err(FsError::NoDevice);
        }
        // Keep the same current-capability/reset checks during PSR and AUX
        // waits as during PTE/plane access; no controller lock spans a wait.
        crate::intel_gpu_edp::kms_inhibit_psr(self).map_err(|_| crate::intel_gpu_user::io_error())
    }
    fn color_takeover(&self) -> Result<(), FsError> {
        if !self.console_access_ok() {
            return Err(FsError::NoDevice);
        }
        inherited_fetchers_idle(self, self.generation)?;
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
    fn recovery_platform(&self, owned_dsb: bool) -> Result<Self, FsError> {
        let mut fresh = self.clone();
        fresh.recovering = true;
        if !fresh.access_ok() {
            return Err(FsError::NoDevice);
        }
        fetchers_idle(&fresh, fresh.generation, owned_dsb)?;
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
}

fn inherited_fetchers_idle(mmio: &impl MmioWindow, generation: Generation) -> Result<(), FsError> {
    fetchers_idle(mmio, generation, false)
}
/// Recovery alone may observe Pipe-A DSB0/1 backed by a retained transport.
/// This grants observation, never retirement: the caller must independently
/// stop source0 then leaf1 before fresh console/color programming.
fn fetchers_idle(
    mmio: &impl MmioWindow,
    generation: Generation,
    owned_dsb: bool,
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
    let count = if generation == Generation::MeteorLake {
        5
    } else {
        7
    };
    for pipe in 0..4u64 {
        let cursor = mmio.read32(0x70080 + pipe * 0x1000);
        if cursor == u32::MAX {
            return Err(FsError::NoDevice);
        }
        if cursor & 0x27 != 0 {
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
    color_unpublished: bool,
    // DMA completion alone cannot publish a cancelled mixed framebuffer.
    mixed_unpublished: bool,
    dsb: Option<crate::intel_gpu_dsb::Owner<M>>,
    dsb_update: Option<crate::intel_gpu_color::Update>,
    joint: Option<Joint>,
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
}

#[derive(Debug)]
pub(crate) struct LegacyGuard<'a, M: Platform = Physical> {
    state: MutexGuard<'a, State<M>>,
    platform: &'a M,
    geometry: &'a IrqSafeSpinLock<Geometry>,
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
    if generation == Generation::PantherLake {
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
    let display = Arc::new(Device::new(platform, generation, bar.len, console));
    let mut displays = DISPLAYS.lock();
    if displays
        .iter()
        .any(|old| old.platform.index == index || old.platform.bar.phys == bar.phys)
    {
        return;
    }
    displays.push(display);
    drop(displays);
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
pub(crate) fn available(index: u32) -> bool {
    display(index).is_some()
}
pub(crate) fn active(index: u32) -> bool {
    display(index).is_some_and(|d| {
        d.platform.reset_lost()
            || d.state.try_lock().is_none_or(|s| {
                s.presenter.is_some()
                    || s.color.is_some()
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
pub(crate) async fn quiesce_for_legacy(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
    if let Some(display) = display_for_bar(bar) {
        display.quiesce().await?;
    }
    Ok(())
}

pub(crate) async fn recover_after_gt_reset(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
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
                color_unpublished: false,
                mixed_unpublished: false,
                dsb: None,
                dsb_update: None,
                joint: None,
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
        state.blocked = true;
        state.failed = true;
        state.paused = true;
        self.platform.pause_console().await;
        if let Some(old) = &state.presenter {
            old.retained_io().poison();
        }
        let fresh = self
            .platform
            .recovery_platform(state.dsb.as_ref().is_some_and(|dsb| dsb.exposed()))?;
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
        let io = unsafe {
            PollIo::after_reset(fresh.clone(), self.generation, Pipe::A, self.bar_len, saved)
        }
        .map_err(|_| crate::intel_gpu_user::io_error())?;
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
        state.current = None;
        state.pending = None;
        state.joint = None;
        state.recovery_status = None;
        // All old IO and mappings are closed before making normal accesses
        // valid again; only this new console witness reopens admission.
        drop(console);
        state.mixed_unpublished = false;
        self.platform.recovery_complete();
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
        Ok(Guard {
            device: self,
            state,
        })
    }
    pub(crate) async fn quiesce(&self) -> Result<(), FsError> {
        let state = self.state.lock().await;
        let mut guard = Guard {
            device: self,
            state,
        };
        guard.restore_console().await?;
        self.platform.color_restored();
        guard.state.blocked = true;
        Ok(())
    }
}
impl<M: Platform> Device<M> {
    pub(crate) fn legacy(&self) -> Result<LegacyGuard<'_, M>, FsError> {
        let state = self.state.try_lock().ok_or(FsError::Busy)?;
        if self.platform.reset_lost()
            || state.presenter.is_some()
            || state.color.is_some()
            || state.color_unpublished
            || state.mixed_unpublished
            || state.paused
            || state.failed
        {
            return Err(FsError::Busy);
        }
        Ok(LegacyGuard {
            state,
            platform: &self.platform,
            geometry: &self.geometry,
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
            let Some(presenter) = self.state.presenter.as_mut() else {
                return Ok(None);
            };
            if !presenter.pending() {
                return Ok(None);
            }
            match presenter.poll(self.device.platform.now()) {
                Ok(Some(completion)) => {
                    if self.device.platform.reset_lost() {
                        self.state.failed = true;
                        return Err(FsError::NoDevice);
                    }
                    if let Some(retired) = completion.retired {
                        if let Err(error) = presenter.release(retired) {
                            self.state.failed = true;
                            return Err(scanout_error(error));
                        }
                    }
                    self.state.current = self.state.pending.take();
                    return Ok(Some(completion.stamp));
                }
                Ok(None) => self.device.platform.tick().await,
                Err(error) => {
                    self.state.failed = true;
                    return Err(scanout_error(error));
                }
            }
        }
    }
    async fn start(&mut self) -> Result<(), FsError> {
        if self.state.presenter.is_some() {
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
        if let Err(error) = self.device.platform.takeover() {
            if self.device.platform.reset_lost() {
                self.state.failed = true;
            } else {
                self.device.platform.resume_console();
                self.state.paused = false;
            }
            return Err(error);
        }
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
        let io = unsafe {
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
        let format = io.format();
        let pat = if self.device.generation == Generation::MeteorLake {
            1
        } else {
            0
        };
        // SAFETY: startup owns the empty display-only arena and the original
        // console allocation remains retained by the registered IntelGpu.
        let presenter = unsafe {
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
        self.state.presenter = Some(presenter);
        Ok(())
    }
    fn prepare_surface(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
    ) -> Result<SurfaceId, FsError> {
        if let Some((current, id)) = &self.state.current {
            if Arc::ptr_eq(current, &object) {
                return Ok(*id);
            }
        }
        self.state
            .presenter
            .as_mut()
            .expect("presenter")
            .prepare(object, geometry)
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
        let id = self.prepare_surface(object.clone(), geometry)?;
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
        self.finish_color().await?;
        if self.state.color_unpublished {
            return Err(FsError::Busy);
        }
        if !self.state.color_owned {
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
        if let Some(presenter) = self.state.presenter.as_ref() {
            if !presenter.console_active() {
                let ticket = self.ticket()?;
                self.state
                    .presenter
                    .as_mut()
                    .expect("presenter")
                    .arm_console(ticket, self.device.platform.now())
                    .map_err(scanout_error)?;
                self.state.pending = None;
                self.finish_pending().await?;
            }
            self.state
                .presenter
                .as_mut()
                .expect("presenter")
                .shutdown_restored_console()
                .map_err(scanout_error)?;
            self.state.presenter = None;
            self.state.current = None;
            self.state.recovery_status = None;
        }
        if self.state.paused && self.state.color.is_none() {
            self.device.platform.resume_console();
            self.state.paused = false;
        }
        Ok(())
    }
    async fn finish_color(&mut self) -> Result<Option<FlipStamp>, FsError> {
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
                    completion.stamp
                } else {
                    stamp
                };
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
        self.set_color_with_dsb(coefficients, lut, None).await
    }
    pub(crate) async fn set_color_with_dsb(
        &mut self,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        dsb_timing: Option<crate::intel_gpu_dsb::Timing>,
    ) -> Result<FlipStamp, FsError> {
        if self.state.mixed_unpublished {
            return Err(FsError::Busy);
        }
        self.color_transaction(coefficients, lut, dsb_timing, None)
            .await
    }
    pub(crate) async fn present_color(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        timing: crate::intel_gpu_dsb::Timing,
    ) -> Result<FlipStamp, FsError> {
        self.check(geometry)?;
        if self.state.color_unpublished || self.state.mixed_unpublished {
            return Err(FsError::Busy);
        }
        if !object.is_wc() || !object.scanout() || object.is_vram() || object.is_userptr() {
            return Err(FsError::Unsupported);
        }
        self.color_transaction(coefficients, lut, Some(timing), Some((object, geometry)))
            .await
    }
    async fn color_transaction(
        &mut self,
        coefficients: Option<[u64; 9]>,
        lut: Option<Arc<crate::intel_gpu_color::Lut>>,
        dsb_timing: Option<crate::intel_gpu_dsb::Timing>,
        primary: Option<(Arc<GemObject>, Geometry)>,
    ) -> Result<FlipStamp, FsError> {
        self.ownership_valid()?;
        self.finish_color().await?;
        self.finish_pending().await?;
        let previously_owned = self.state.color_owned;
        let had_presenter = self.state.presenter.is_some();
        let previous_mixed = self.state.mixed_unpublished;
        if self.state.color.is_none() {
            let owner = crate::intel_gpu_color::Owner::capture(
                &self.device.platform,
                self.device.generation,
            )?;
            self.state.color = Some(owner);
        }
        if !self.state.color_owned {
            self.state.paused = true;
            self.device.platform.pause_console().await;
            if let Err(error) = self.device.platform.color_takeover() {
                // The original was retained before pausing; no CSC write has
                // occurred. Lost authority keeps the owner quarantined.
                if self.device.platform.reset_lost() {
                    self.state.failed = true;
                } else {
                    self.state.color = None;
                    self.state.color_owned = false;
                    if self.state.presenter.is_none() {
                        self.device.platform.resume_console();
                        self.state.paused = false;
                    }
                }
                return Err(error);
            }
            self.state.color_owned = true;
        }
        let unpublished = core::mem::replace(&mut self.state.color_unpublished, true);
        let arm = if let Some(timing) = dsb_timing {
            async {
                self.device.platform.takeover()?; // live PAT/GT + PSR ownership
                if self.state.dsb.is_none() {
                    let dsb = crate::intel_gpu_dsb::Owner::reserve(
                        self.device.platform.clone(),
                        self.device.bar_len,
                    )
                    .map_err(|error| {
                        if error == FsError::NotImplemented {
                            FsError::Unsupported
                        } else {
                            error
                        }
                    })?;
                    self.state.dsb = Some(dsb);
                }
                let surface = if let Some((object, geometry)) = &primary {
                    self.start().await?;
                    let id = self.prepare_surface(object.clone(), *geometry)?;
                    let ticket = self.ticket()?;
                    self.state.pending = Some((object.clone(), id));
                    self.state.mixed_unpublished = true;
                    self.state.joint = Some(Joint {
                        staged: false,
                        completion: None,
                    });
                    let arm = self
                        .state
                        .presenter
                        .as_mut()
                        .expect("joint presenter")
                        .stage_dsb(id, ticket, self.device.platform.now())
                        .map_err(scanout_error)?;
                    self.state.joint.as_mut().expect("joint state").staged = true;
                    Some(arm)
                } else {
                    None
                };
                let mut update = self
                    .state
                    .color
                    .as_mut()
                    .expect("color owner")
                    .prepare_dsb(&self.device.platform, coefficients, lut.clone())?;
                if let Some(surface) = surface {
                    update.registers.push(surface);
                }
                self.state.dsb_update = Some(update);
                let state = &mut *self.state;
                let update = state.dsb_update.as_ref().expect("DSB color image");
                state.dsb.as_mut().expect("DSB owner").arm(
                    timing,
                    &update.registers,
                    update.lut(),
                    self.device.platform.now(),
                )
            }
            .await
        } else {
            self.state.color.as_mut().expect("color owner").arm_color(
                &self.device.platform,
                coefficients,
                lut.clone(),
                self.device.platform.now(),
            )
        };
        if let Err(error) = arm {
            // Unsupported is confined to preflight before this attempt
            // writes command memory, PTEs, or controls. Preserve a parked
            // installed BO/VA while unwinding this unexposed color update.
            let prewrite = error == FsError::Unsupported
                && self.state.dsb.as_ref().is_none_or(|dsb| !dsb.armed());
            if prewrite {
                self.rollback_joint_before_arm()?;
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
                    if self.state.presenter.is_none() {
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
        if coefficients.is_none() && lut.is_none() {
            self.state.color = None;
            self.state.color_owned = false;
            if self.state.presenter.is_none() && self.state.paused {
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
        self.finish_color().await?;
        if self.state.color.is_some() {
            // Internal full restoration may clear color while keeping the
            // mixed marker until independent primary restoration also ends.
            self.color_transaction(None, None, None, None).await?;
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_kms_tests.rs"]
pub(crate) mod tests;
