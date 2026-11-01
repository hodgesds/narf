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
    intel_gpu_scanout_io::{DisplayAccess, PollIo},
};

type Wait<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// The production implementation retains PCI authority and a permanent UC
/// BAR. Tests implement the same platform boundary with native register models.
pub(crate) trait Platform:
    DisplayAccess + Clone + core::fmt::Debug + Send + Sync + 'static
{
    fn takeover(&self) -> Result<(), FsError>;
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
}
impl MmioWindow for Physical {
    fn read32(&self, offset: u64) -> u32 {
        if self.reset_lost() {
            u32::MAX
        } else {
            self.window.read32(offset)
        }
    }
    fn write32(&self, offset: u64, value: u32) {
        if !self.reset_lost() {
            self.window.write32(offset, value);
        }
    }
}
// SAFETY: this window is used only under the per-card KMS mutex. Every
// modeset/power path must first quiesce and acquire its legacy guard. The
// function's iGPU runtime-PM owner forbids autosuspend with an active panel.
// AuthorizedWindow invokes the current capability for each MMIO access.
unsafe impl DisplayAccess for Physical {
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
        if self.reset_lost() {
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
}

fn inherited_fetchers_idle(mmio: &impl MmioWindow, generation: Generation) -> Result<(), FsError> {
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
            if ctl & ((1 << 31) | 1) != 0 {
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
struct State<M: Platform> {
    console: ActiveScanout,
    presenter: Option<Presenter<PollIo<M>>>,
    current: Option<(Arc<GemObject>, SurfaceId)>,
    pending: Option<(Arc<GemObject>, SurfaceId)>,
    next_ticket: u64,
    paused: bool,
    blocked: bool,
    failed: bool,
}

#[derive(Debug)]
pub(crate) struct Device<M: Platform> {
    platform: M,
    generation: Generation,
    bar_len: u64,
    state: Mutex<State<M>>,
}
pub(crate) type Display = Device<Physical>;
pub(crate) type Session<'a> = Guard<'a, Physical>;

#[derive(Debug)]
pub(crate) struct Guard<'a, M: Platform> {
    device: &'a Device<M>,
    state: MutexGuard<'a, State<M>>,
}

#[derive(Debug)]
pub(crate) struct LegacyGuard<'a, M: Platform = Physical> {
    state: MutexGuard<'a, State<M>>,
    platform: &'a M,
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
        card.lock().native_atomic = true;
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
            || d.state
                .try_lock()
                .is_none_or(|s| s.presenter.is_some() || s.paused || s.failed)
    })
}

/// Called after publishing backend epoch zero and before an automatic GT
/// reset, while the GT reset mutex is held. Never await or wait for display
/// ownership here: a display transaction may itself await a GT fence.
/// A busy/owned display loses its witnesses permanently; GEM pages and the
/// paused console remain quarantined until reboot. GT reset is no fetch-stop
/// proof, and this path must neither unpin a front nor restore status bits.
pub(crate) fn quarantine_for_gt_reset(bar: &narf_bus::MmioRegion) {
    if let Some(display) = display_for_bar(bar) {
        quarantine_reset_state(&display.state, &display.platform.reset_lost);
    }
}

fn quarantine_reset_state<M: Platform>(state: &Mutex<State<M>>, lost: &AtomicBool) {
    if let Some(mut state) = state.try_lock() {
        if lost.load(Ordering::Acquire) || state.presenter.is_some() || state.paused || state.failed
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

impl<M: Platform> Device<M> {
    fn new(platform: M, generation: Generation, bar_len: u64, console: ActiveScanout) -> Self {
        Self {
            platform,
            generation,
            bar_len,
            state: Mutex::new(State {
                console,
                presenter: None,
                current: None,
                pending: None,
                next_ticket: 1,
                paused: false,
                blocked: false,
                failed: false,
            }),
        }
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
        guard.state.blocked = true;
        Ok(())
    }
}
impl<M: Platform> Device<M> {
    pub(crate) fn legacy(&self) -> Result<LegacyGuard<'_, M>, FsError> {
        let state = self.state.try_lock().ok_or(FsError::Busy)?;
        if self.platform.reset_lost() || state.presenter.is_some() || state.paused || state.failed {
            return Err(FsError::Busy);
        }
        Ok(LegacyGuard {
            state,
            platform: &self.platform,
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
    pub(crate) async fn present(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
    ) -> Result<FlipStamp, FsError> {
        self.check(geometry)?;
        if !object.is_wc() || !object.scanout() || object.is_vram() || object.is_userptr() {
            return Err(FsError::Unsupported);
        }
        self.finish_pending().await?;
        self.start().await?;
        let id = if let Some((current, id)) = &self.state.current {
            if Arc::ptr_eq(current, &object) {
                *id
            } else {
                self.state
                    .presenter
                    .as_mut()
                    .expect("presenter")
                    .prepare(object.clone(), geometry)
                    .map_err(scanout_error)?
            }
        } else {
            self.state
                .presenter
                .as_mut()
                .expect("presenter")
                .prepare(object.clone(), geometry)
                .map_err(scanout_error)?
        };
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
        }
        if self.state.paused {
            self.device.platform.resume_console();
            self.state.paused = false;
        }
        Ok(())
    }
    pub(crate) async fn wait_vblank(&mut self) -> Result<FlipStamp, FsError> {
        if self.state.presenter.is_some() || self.state.failed {
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
mod tests;
