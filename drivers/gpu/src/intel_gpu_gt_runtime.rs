//! Per-PCI-function GT startup and scheduling service. No singleton GT BAR or
//! ambient firmware bytes: every instance retains its card, PCI authority,
//! runtime-PM hold, GGTT arena and complete GuCGt graph through stop/reset.

use crate::{
    drm_devfs_bridge::IntelGpuCard,
    intel_gpu_aux::MmioWindow,
    intel_gpu_fence::CompletionFence,
    intel_gpu_gt::GtPlatform,
    intel_gpu_gt_hw::AuthorizedWindow,
    intel_gpu_guc_boot::BootConfig,
    intel_gpu_guc_firmware::GuCFirmware,
    intel_gpu_guc_gt::{GtError, GtState, GuCGt},
    intel_gpu_rcs::{GgttArena, SharedArena},
};
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Read, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_power::runtime_pm::{RpmError, RpmFuture, RpmStatus, RuntimePmOps, SchedulerEnv};

#[path = "intel_gpu_d3cold.rs"]
pub(crate) mod d3cold;
#[path = "intel_gpu_display_rpm.rs"]
pub(crate) mod display_rpm;
#[path = "intel_gpu_gt_recovery.rs"]
pub(crate) mod recovery;

type ProductionGt = GuCGt<AuthorizedWindow, SharedArena>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RuntimeError {
    Device,
    Authority,
    Firmware(crate::intel_gpu_guc_firmware::FirmwareError),
    State,
    Configuration,
    Takeover(crate::intel_gpu_gt::lnl::Error),
    Gt(GtError),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Cold,
    Powering,
    Takeover,
    Booting,
    Discovering,
    Reloading,
    Ct,
    Probe,
    Defaults,
    PpgttProbe,
    Huc,
    /// Source-qualified host-L2 preparation and acknowledged MERT sanitize.
    Mert,
    /// Fresh GT is ready; display retirement runs outside the GT mutex.
    DisplayRecovery,
    Running,
    /// Runtime-suspended after a verified idle stop; D3hot is owned by the
    /// PCI runtime-PM layer. Resume restarts from Cold under the same epoch.
    Parked,
    Stopped,
    Failed,
    Cleaning,
}

struct State {
    coredump: Option<crate::intel_gpu_error::coredump::Armed>,
    coredump_enabled: bool,
    coredump_retry_ns: u64,
    irq: Option<crate::intel_gpu_gt_irq::GtIrq>,
    irq_tried: bool,
    gt: Option<ProductionGt>,
    firmware: Option<GuCFirmware>,
    /// The device's HuC image: GT0's on exact TGL, the media GT's on
    /// MTL/Arrow (xe_huc.c::xe_huc_init).
    huc: Option<crate::intel_gpu_huc::Firmware>,
    probe: Option<Arc<CompletionFence>>,
    recovery: recovery::Coordinator,
    phase: Phase,
    firmware_frame: Option<(crate::intel_gpu_pipes::Pipe, u32, u64)>,
    saved: Option<narf_bus::pci::SavedPciConfig>,
    power_ready: u64,
    /// User epoch to continue after a runtime resume (clean idle stop only).
    parked_epoch: Option<(u64, crate::intel_gpu_engine::EngineSet, (u8, u8))>,
    /// CPU access to local memory while runtime-suspended: the LMEM BAR's
    /// user mappings revoked and kernel access closed. Ended when a resumed
    /// GT is published running again (xe_pm_runtime_suspend's
    /// vram_userfault release and __xe_bo_cpu_fault's resume).
    vram_cpu: Option<VramCpuRevocation>,
    /// The SLPC outcome of this GT incarnation has been logged.
    slpc_reported: bool,
    /// Immutable boot choice initially; changed only by a client-free reset
    /// transaction. Clean runtime resume preserves this exact owner policy.
    ccs_mode: Result<u8, RuntimeError>,
    lnl_flr: Option<crate::intel_gpu_gt::lnl::DriverFlr>,
    lnl_receipt: Option<crate::intel_gpu_gt::lnl::Receipt>,
    lnl_clients: Option<crate::intel_gpu_ccs_control::TakeoverClients>,
    smallbar_takeover: Option<crate::intel_gpu_gt::smallbar::Takeover>,
    smallbar_authority: Option<Arc<crate::intel_gpu_gt::smallbar::Authority>>,
    smallbar_grant_deadline: Option<u64>,
    /// MTL/Arrow standalone media GT owner of this running GT0 incarnation.
    /// Its refusal is terminal for the incarnation and never reaches GT0.
    media: Option<crate::intel_gpu_gt::media::MediaGt>,
    media_reported: bool,
    /// Media GuC beside GT0. It holds firmware/CT memory in GT0's shared GGTT
    /// arena, so no GT0 restart or D3 may proceed until its stop is proven.
    media_guc: Option<crate::intel_gpu_gt::media::MediaGuc<AuthorizedWindow, SharedArena>>,
    media_guc_tried: bool,
    media_guc_reported: bool,
    /// One media-GT reset/recovery per GT0 incarnation after a media GuC fault.
    media_recovered: bool,
    /// Routing GT1's VCS/VECS onto GT0's delivery failed; GT1 stays polled.
    media_irq_failed: bool,
    /// A media GuC of this owner authenticated `huc` itself. Only then may a
    /// later media GuC adopt a HuC that survived its GuC/GT reset as
    /// RUNNING (xe_huc.c::xe_huc_auth); kept for the owner's lifetime.
    media_huc_established: bool,
    /// The current media GuC's HuC outcome has been logged.
    media_huc_reported: bool,
    /// `narf.intel.gsc=1` beside the media GT: the GSC (struct xe_gsc) for
    /// the device's lifetime. Its private object is never released.
    gsc: Option<GscOwner>,
    /// The GSC status last logged.
    gsc_reported: Option<crate::intel_gpu_gt::media::gsc::load::Status>,
    /// Routing the GSC sources onto GT0's delivery failed; the GSC is polled.
    gsc_irq_failed: bool,
    /// `narf.intel.pxp=1` beside the GSC: struct xe_pxp and its hardware
    /// half for the device's lifetime, once xe_pxp_init succeeded (tried
    /// once per device, on the first eligible GT1).
    pxp: crate::intel_gpu_gt::media::pxp::Runtime<crate::intel_gpu_gt::media::pxp::GemClient>,
    /// Routing the KCR causes failed: terminations then never complete and
    /// a start that needs one times out.
    kcr_irq_failed: bool,
}

type GscOwner = crate::intel_gpu_gt::media::gsc::owner::GscOwner<
    SharedArena,
    crate::intel_gpu_stolen::Bar2Window,
>;

/// The DSM access of the GSC private object: the function's BAR2 (when it is
/// this function's controller), PCI BSM, GGTT PTE reads through the
/// authorized window, and the page allocator's RAM proof.
struct GscDsm<'a> {
    pending: &'a Pending,
    gmadr: Option<narf_bus::bar::MmioRegion>,
}

impl<'a> GscDsm<'a> {
    fn new(pending: &'a Pending) -> Self {
        let gmadr = crate::intel_gpu::with_controller(|gpu| {
            (gpu.gtt_mmadr.phys == pending.bar.phys).then_some(gpu.gmadr)
        })
        .flatten();
        Self { pending, gmadr }
    }
}

impl crate::intel_gpu_gt::media::gsc::owner::DsmPort for GscDsm<'_> {
    type Cpu = crate::intel_gpu_stolen::Bar2Window;
    fn layout(&self) -> Option<(crate::intel_gpu_stolen::Layout, u64)> {
        use crate::intel_gpu_stolen as dsm;
        let gmadr = self.gmadr?;
        let config = |offset| {
            narf_bus::pci::read_config32(&self.pending.cap, &self.pending.device, offset).ok()
        };
        dsm::discover(
            &self.pending.window,
            (gmadr.phys.raw(), gmadr.len),
            (config(dsm::PCI_BSM_DW0)?, config(dsm::PCI_BSM_DW1)?),
            self.pending.bar.len,
        )
    }
    fn pte(&self, index: u64) -> u64 {
        let at = crate::intel_gpu_gtt::GGTT_ARRAY_BASE + 8 * index;
        u64::from(self.pending.window.read32(at))
            | u64::from(self.pending.window.read32(at + 4)) << 32
    }
    fn system_ram(&self, phys: u64) -> bool {
        narf_memory::frame::is_system_ram(narf_memory::PhysAddr::new(phys))
    }
    fn cpu(&self) -> Self::Cpu {
        // `layout` refuses without BAR2, so no object is placed then; an
        // empty window refuses every access regardless.
        crate::intel_gpu_stolen::Bar2Window(self.gmadr.unwrap_or(narf_bus::bar::MmioRegion {
            len: 0,
            ..self.pending.bar
        }))
    }
}

use crate::intel_gpu_gt::media::Retire as MediaRetire;

#[derive(Clone, Copy)]
enum DisplayOwner {
    Standard,
    LunarLake,
    PantherLake,
    Firmware(crate::intel_gpu::FirmwareRenderHandoff),
    /// Nova Lake-S display 35 still scanning its firmware primary
    /// (`narf.intel.nvl_display`): fixed-mode KMS, and the GT starts
    /// display-preserving beside it, never with the headless driver FLR.
    NovaLake,
    /// Nova Lake-S display 35 owned by its route (`narf.intel.nvl_modeset`):
    /// the panel lit through the LT PHY, an owned console with its KMS owner,
    /// and the display-preserving GT beside it. Turns the panel off before
    /// system suspend and relights it on resume (`intel_gpu_xe3plpd::relight`).
    NovaLakeOwned,
}

/// Whether a GT owner beside `display` may take part in system suspend. A
/// retained firmware surface (a Gen12 GOP or Nova's firmware primary) has no
/// S3 relight owner; Nova's owned route does.
const fn display_suspend_admitted(display: DisplayOwner, smallbar: bool) -> bool {
    !matches!(display, DisplayOwner::Firmware(_) | DisplayOwner::NovaLake)
        && system_suspend_admitted(
            smallbar,
            matches!(
                display,
                DisplayOwner::LunarLake | DisplayOwner::PantherLake | DisplayOwner::NovaLakeOwned
            ),
        )
}

struct Pending {
    index: u32,
    card: Arc<IntelGpuCard>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: narf_bus::bar::MmioRegion,
    mode: Option<crate::intel_gpu_modeset::Mode>,
    smallbar: bool,
    display: DisplayOwner,
    window: AuthorizedWindow,
    /// A discrete function probed with a lit display keeps D0.
    display_lit: bool,
}

impl Pending {
    fn allows_system_suspend(&self) -> bool {
        display_suspend_admitted(self.display, self.smallbar)
    }
}

/// The integrated Xe2/Xe3 GT profile of one function (§17 10.5).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum LnlProfile {
    /// Headless main GT: client-free cold start through a driver FLR, which
    /// also resets display and stolen memory. Unchanged by the display route.
    Headless,
    /// Lunar Lake display-20 function: the route's lit panel is preserved.
    /// No driver FLR; `lnl::Receipt::admit_display`, then the GT-only reset
    /// `HardwareInit` runs before the first PTE.
    DisplayPreserving,
}

/// Select the integrated GT profile. `None` is either not an integrated
/// Xe2/Xe3 profile or a refused combination (a display route on anything but
/// Lunar Lake, or one without a lit panel mode).
pub(crate) fn lnl_profile(
    platform: GtPlatform,
    lnl_display: bool,
    has_mode: bool,
) -> Option<LnlProfile> {
    if !platform.is_headless_integrated() {
        return None;
    }
    match (lnl_display, platform.is_lnl() && has_mode) {
        (false, _) => Some(LnlProfile::Headless),
        (true, true) => Some(LnlProfile::DisplayPreserving),
        (true, false) => None,
    }
}

/// [`lnl_profile`] for the Panther Lake display-30 route: the
/// display-preserving profile only for Panther Lake with the route and a lit
/// mode; `Headless` for every other LNL/PTL function. Lunar Lake's
/// selection is [`lnl_profile`]'s, unchanged.
pub(crate) fn ptl_profile(
    platform: GtPlatform,
    ptl_display: bool,
    has_mode: bool,
) -> Option<LnlProfile> {
    if !platform.is_headless_integrated() {
        return None;
    }
    match (ptl_display, platform.has_ptl_display_route() && has_mode) {
        (false, _) => Some(LnlProfile::Headless),
        (true, true) => Some(LnlProfile::DisplayPreserving),
        (true, false) => None,
    }
}

/// [`lnl_profile`] for Nova Lake-S's owned display-35 route: the
/// display-preserving profile only for Nova Lake-S with the owned route and
/// its lit mode; `Headless` for every function without the route.
pub(crate) fn nvl_profile(
    platform: GtPlatform,
    nvl_owned: bool,
    has_mode: bool,
) -> Option<LnlProfile> {
    if !platform.is_headless_integrated() {
        return None;
    }
    match (nvl_owned, platform == GtPlatform::NovaLakeS && has_mode) {
        (false, _) => Some(LnlProfile::Headless),
        (true, true) => Some(LnlProfile::DisplayPreserving),
        (true, false) => None,
    }
}

/// Small-BAR discrete profiles remain D0-only until aperture-free CPU/GTT
/// eviction lands; Display 20 (Lunar Lake), Display 30 (Panther Lake) and
/// Nova Lake-S's owned display 35 own panel power-off/on and relight across
/// S3.
pub(crate) const fn system_suspend_admitted(smallbar: bool, _lnl_display: bool) -> bool {
    !smallbar
}

struct Owner {
    pending: Pending,
    pm: narf_power::runtime_pm_pci::PciRuntimeNode,
    /// How this owner takes part in runtime PM, fixed at start.
    profile: Result<display_rpm::Profile, display_rpm::ProfileRefusal>,
    /// Autosuspend has been configured and runtime PM allowed.
    autosuspend: AtomicBool,
    /// The runtime-PM reference a system sleep holds from preparation to
    /// resume (`pci_pm_suspend` resumes a runtime-suspended function first).
    system_awake: IrqSafeSpinLock<Option<Awake>>,
    runtime_power: Arc<crate::intel_gpu_power_controls::runtime::Control>,
    state: Mutex<State>,
    suspended: AtomicBool,
    user_epoch: Arc<AtomicU64>,
    log_publication: Arc<crate::intel_gpu_guc_log::stream::Publication>,
    reset_publication: Arc<recovery::Publication>,
    user_version: Arc<AtomicU32>,
    user_engines: Arc<core::sync::atomic::AtomicU32>,
    /// Published standalone media GT (native Xe gt_id 1), opt-in only.
    user_media: Arc<IrqSafeSpinLock<Option<crate::intel_gpu_user::MediaGtStatus>>>,
    /// `xe->pxp` once xe_pxp_init succeeded (`narf.intel.pxp=1`).
    user_pxp: IrqSafeSpinLock<Option<Arc<crate::intel_gpu_gt::media::pxp::Pxp>>>,
    user_facts: Arc<IrqSafeSpinLock<Option<crate::intel_gpu_user::DeviceFacts>>>,
    eu_info: IrqSafeSpinLock<Option<crate::intel_gpu_eu_stall::Info>>,
    oa_info: IrqSafeSpinLock<Option<crate::intel_gpu_oa::Device>>,
    power_controls: Arc<crate::intel_gpu_power_controls::PowerControls>,
    hwmon: Option<Arc<crate::intel_gpu_hwmon::Monitor>>,
    ccs_control: Option<Arc<crate::intel_gpu_ccs_control::Control>>,
}

#[derive(Debug)]
struct Backend {
    owner: Weak<Owner>,
    epoch: Arc<AtomicU64>,
    version: Arc<AtomicU32>,
    engines: Arc<core::sync::atomic::AtomicU32>,
    media: Arc<IrqSafeSpinLock<Option<crate::intel_gpu_user::MediaGtStatus>>>,
    platform: GtPlatform,
    facts: Arc<IrqSafeSpinLock<Option<crate::intel_gpu_user::DeviceFacts>>>,
    power_controls: Arc<crate::intel_gpu_power_controls::PowerControls>,
    ccs_control: Option<Arc<crate::intel_gpu_ccs_control::Control>>,
}

impl crate::intel_gpu_user::UserBackend for Backend {
    fn cpu_vram_wakeref(&self) -> narf_filesystem::FsFuture<'_, Box<dyn core::any::Any + Send>> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let awake = owner.vram_wakeref().await?;
            Ok(Box::new(awake) as Box<dyn core::any::Any + Send>)
        })
    }
    fn reset_availability_epoch(&self) -> Option<u64> {
        let owner = self.owner.upgrade()?;
        if owner.suspended.load(Ordering::Acquire) {
            return None;
        }
        owner
            .reset_publication
            .epoch(self.platform, self.epoch.load(Ordering::Acquire))
    }
    fn eu_stall_info(&self) -> Option<crate::intel_gpu_eu_stall::Info> {
        if !crate::intel_gpu_eu_stall::supported(self.platform)
            || self.epoch.load(Ordering::Acquire) == 0
        {
            return None;
        }
        let owner = self.owner.upgrade()?;
        let info = *owner.eu_info.lock();
        info.filter(|info| info.platform == self.platform)
    }
    fn eu_stall_control(
        &self,
        session: Arc<crate::intel_gpu_eu_stall::Session>,
        operation: crate::intel_gpu_eu_stall::Operation,
    ) -> narf_filesystem::FsFuture<'_, ()> {
        Box::pin(async move {
            use narf_filesystem::FsError;
            let owner = self.owner.upgrade().ok_or(FsError::NoDevice)?;
            let _awake = Awake::take(&owner).await?;
            let epoch = owner.user_epoch.load(Ordering::Acquire);
            let deadline = narf_time::monotonic_ns().saturating_add(50_000_000);
            loop {
                let mut state = owner.lock_running().await;
                if !crate::intel_gpu_eu_stall::capable() {
                    session.fail(FsError::OperationNotPermitted);
                    return Err(FsError::OperationNotPermitted);
                }
                if epoch == 0
                    || epoch != owner.user_epoch.load(Ordering::Acquire)
                    || state.phase != Phase::Running
                    || owner.suspended.load(Ordering::Acquire)
                    || session.info().card != owner.pending.index
                {
                    return Err(FsError::NoDevice);
                }
                let result = state
                    .gt
                    .as_mut()
                    .ok_or(FsError::NoDevice)?
                    .control_eu_stall(session.clone(), operation, || {
                        crate::intel_gpu_eu_stall::capable()
                            && narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                                == Ok(Some(narf_bus::pci::PciPowerState::D0))
                    });
                if result != Err(FsError::WouldBlock) {
                    return result;
                }
                drop(state);
                if narf_time::monotonic_ns() >= deadline {
                    session.fail(FsError::Busy);
                    return Err(FsError::Busy);
                }
                narf_scheduler::yield_now().await;
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
            }
        })
    }
    fn oa_device(&self) -> Option<crate::intel_gpu_oa::Device> {
        if self.epoch.load(Ordering::Acquire) == 0 {
            return None;
        }
        let owner = self.owner.upgrade()?;
        let device = *owner.oa_info.lock();
        device.filter(|device| device.platform == self.platform)
    }
    fn oa_control(
        &self,
        session: Arc<crate::intel_gpu_oa::Session>,
        request: crate::intel_gpu_oa::Request,
    ) -> narf_filesystem::FsFuture<'_, ()> {
        Box::pin(async move {
            use narf_filesystem::FsError;
            let owner = self.owner.upgrade().ok_or(FsError::NoDevice)?;
            let _awake = Awake::take(&owner).await?;
            let epoch = owner.user_epoch.load(Ordering::Acquire);
            let jobs = owner
                .oa_locked(epoch, &session, |gt, now, access| {
                    gt.oa_begin(&session, &request, now, access)
                })
                .await?;
            let configured = !jobs.is_empty();
            // xe_oa_emit_oa_config: each job retires before the next queues.
            for job in &jobs {
                let fence = owner
                    .oa_locked(epoch, &session, |gt, now, _| {
                        gt.submit_oa_job(now, &session, job)
                    })
                    .await?;
                if fence.wait().await.is_err() {
                    session.fail(FsError::NoDevice);
                    return Err(FsError::NoDevice);
                }
            }
            if configured {
                // NOA_PROGRAM_ADDITIONAL_DELAY_US after the job fence.
                narf_time::SleepUntil::new(
                    narf_time::Deadline::after_us(crate::intel_gpu_oa::NOA_DELAY_NS / 1000)
                        .as_instant(),
                )
                .await;
            }
            owner
                .oa_locked(epoch, &session, |gt, now, access| {
                    gt.oa_finish(&session, &request, now, access)
                })
                .await
        })
    }
    fn oa_read<'a>(
        &'a self,
        session: Arc<crate::intel_gpu_oa::Session>,
        output: &'a mut [u8],
        blocking: bool,
    ) -> narf_filesystem::FsFuture<'a, usize> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let epoch = owner.user_epoch.load(Ordering::Acquire);
            owner
                .oa_locked(epoch, &session, |gt, _, access| {
                    gt.oa_read(&session, &mut *output, blocking, access)
                })
                .await
        })
    }
    fn huc_version(&self) -> narf_filesystem::FsFuture<'_, (u8, u8, u8)> {
        Box::pin(async move {
            use narf_filesystem::FsError;
            let owner = self.owner.upgrade().ok_or(FsError::NoDevice)?;
            let state = owner.state.lock().await;
            let epoch = owner.user_epoch.load(Ordering::Acquire);
            if state.phase != Phase::Running
                || epoch == 0
                || owner.suspended.load(Ordering::Acquire)
            {
                return Err(FsError::NoDevice);
            }
            let current = || {
                narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
            };
            // MTL/Arrow report the media GT's HuC (GT1 publication and epoch)
            // and GT0 never answers; older media reports GT0's.
            crate::intel_gpu_gt::media::query_huc(
                self.platform,
                state.media_guc.as_ref(),
                current,
                || state.gt.as_ref()?.huc_version(epoch, current),
            )
            .ok_or(FsError::NoDevice)
        })
    }
    fn ccs_control(&self) -> Option<Arc<crate::intel_gpu_ccs_control::Control>> {
        self.ccs_control.clone()
    }
    fn guc_log_snapshot(
        &self,
        buffer: crate::intel_gpu_guc_log::CaptureBuffer,
    ) -> narf_filesystem::FsFuture<'_, crate::intel_gpu_guc_log::Snapshot> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            if buffer.index() != owner.pending.index {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            // Passive diagnostics never resume/reboot an idle or lost GT.
            // This reset/power mutex excludes park/S3 throughout the bounded
            // synchronous copy; each chunk rechecks current D0 and wake.
            let state = owner.state.lock().await;
            let epoch = owner.user_epoch.load(Ordering::Acquire);
            if state.phase != Phase::Running
                || epoch == 0
                || owner.suspended.load(Ordering::Acquire)
            {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            let digest = state
                .firmware
                .as_ref()
                .ok_or(narf_filesystem::FsError::NoDevice)?
                .digest;
            state
                .gt
                .as_ref()
                .ok_or(narf_filesystem::FsError::NoDevice)?
                .snapshot_guc_log(buffer, epoch, narf_time::monotonic_ns(), digest, || {
                    narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                        == Ok(Some(narf_bus::pci::PciPowerState::D0))
                })
        })
    }
    fn guc_log_stream(
        &self,
        session: Arc<crate::intel_gpu_guc_log::StreamSession>,
    ) -> narf_filesystem::FsFuture<'_, ()> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            // Opening a diagnostic stream never wakes/reboots an idle GT.
            let mut state = owner.state.lock().await;
            let epoch = owner.user_epoch.load(Ordering::Acquire);
            if session.index() != owner.pending.index
                || state.phase != Phase::Running
                || epoch == 0
                || owner.suspended.load(Ordering::Acquire)
                || narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                    != Ok(Some(narf_bus::pci::PciPowerState::D0))
            {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            let digest = state
                .firmware
                .as_ref()
                .ok_or(narf_filesystem::FsError::NoDevice)?
                .digest;
            state
                .gt
                .as_mut()
                .ok_or(narf_filesystem::FsError::NoDevice)?
                .attach_log_stream(session, epoch, narf_time::monotonic_ns(), digest)
        })
    }
    fn clear_system_ccs(
        &self,
        object: Arc<crate::intel_gpu_gem::GemObject>,
        epoch: u64,
    ) -> narf_filesystem::FsFuture<'_, Option<Arc<CompletionFence>>> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let awake = Awake::take(&owner).await?;
            let mut state = owner.lock_running().await;
            if state.phase != Phase::Running
                || epoch == 0
                || owner.user_epoch.load(Ordering::Acquire) != epoch
                || owner.suspended.load(Ordering::Acquire)
            {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            let gt = state
                .gt
                .as_mut()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let fence = gt
                .clear_system_ccs(narf_time::monotonic_ns(), object, epoch)
                .map_err(|error| match error {
                    GtError::Busy => narf_filesystem::FsError::WouldBlock,
                    _ => narf_filesystem::FsError::NoDevice,
                })?;
            if let Some(fence) = &fence {
                awake.until(fence.clone());
            }
            Ok(fence)
        })
    }
    fn clear_vram(
        &self,
        object: Arc<crate::intel_gpu_gem::GemObject>,
        epoch: u64,
    ) -> narf_filesystem::FsFuture<'_, Arc<CompletionFence>> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let mut awake = Some(Awake::take(&owner).await?);
            let mut state = owner.lock_running().await;
            if state.phase != Phase::Running
                || epoch == 0
                || owner.user_epoch.load(Ordering::Acquire) != epoch
                || owner.suspended.load(Ordering::Acquire)
            {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            let pool = crate::drm_registry::DrmCard::intel_vram(&*owner.pending.card)
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            if !object.in_vram_pool(&pool) {
                return Err(narf_filesystem::FsError::InvalidData);
            }
            if owner.pending.smallbar {
                match pool.smallbar_access(&owner.pending.window) {
                    Ok(()) => {}
                    Err(crate::intel_gpu_gt::lnl::Error::Busy) => {
                        return Err(narf_filesystem::FsError::WouldBlock);
                    }
                    Err(_) => {
                        owner.close_controls();
                        owner.close_user_epoch();
                        if let Some(gt) = state.gt.as_mut() {
                            let _ = gt.poll_with_access(narf_time::monotonic_ns(), || false);
                        }
                        return Err(narf_filesystem::FsError::NoDevice);
                    }
                }
            }
            if narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                != Ok(Some(narf_bus::pci::PciPowerState::D0))
            {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            if state
                .gt
                .as_ref()
                .is_none_or(|gt| gt.vram_layout() != Some(pool.layout))
            {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            if object.is_gpu_only() {
                if !owner.pending.smallbar {
                    return Err(narf_filesystem::FsError::NoDevice);
                }
                let gt = state
                    .gt
                    .as_mut()
                    .ok_or(narf_filesystem::FsError::NoDevice)?;
                let result = gt.clear_vram(narf_time::monotonic_ns(), object, epoch);
                if gt.state() == GtState::Lost
                    || matches!(
                        result,
                        Err(GtError::State
                            | GtError::Unavailable
                            | GtError::WakeLost
                            | GtError::WakeTimeout)
                    )
                {
                    let _ = gt.poll_with_access(narf_time::monotonic_ns(), || false);
                    owner.close_controls();
                    owner.close_user_epoch();
                }
                let fence = result.map_err(|error| {
                    if matches!(error, GtError::Busy) {
                        narf_filesystem::FsError::WouldBlock
                    } else {
                        narf_filesystem::FsError::NoDevice
                    }
                })?;
                awake
                    .take()
                    .expect("GPU clear PM hold")
                    .until(fence.clone());
                return Ok(fence);
            }
            if !pool.requires_ccs_clear() {
                let mut clear = object.begin_cpu_vram_clear()?;
                // Reserve before any BAR write. Busy callers still own only
                // untouched private storage and can be cancelled immediately.
                let reserve_deadline = narf_time::monotonic_ns().saturating_add(100_000_000);
                let lease = loop {
                    if owner.user_epoch.load(Ordering::Acquire) != epoch {
                        return Err(narf_filesystem::FsError::NoDevice);
                    }
                    let access = state
                        .gt
                        .as_ref()
                        .ok_or(narf_filesystem::FsError::NoDevice)?
                        .vram_access(epoch);
                    if matches!(access, Err(GtError::Busy)) {
                        if narf_time::monotonic_ns() >= reserve_deadline {
                            return Err(narf_filesystem::FsError::WouldBlock);
                        }
                        drop(state);
                        narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant())
                            .await;
                        state = owner.state.lock().await;
                        continue;
                    }
                    if state.phase != Phase::Running
                        || owner.suspended.load(Ordering::Acquire)
                        || narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                            != Ok(Some(narf_bus::pci::PciPowerState::D0))
                        || !state.gt.as_ref().is_some_and(|gt| {
                            access.is_ok() && gt.vram_layout() == Some(pool.layout)
                        })
                    {
                        if owner.pending.smallbar {
                            if let Some(gt) = state.gt.as_mut() {
                                let _ = gt.poll_with_access(narf_time::monotonic_ns(), || false);
                            }
                        }
                        owner.close_controls();
                        owner.close_user_epoch();
                        return Err(narf_filesystem::FsError::NoDevice);
                    }
                    match state
                        .gt
                        .as_mut()
                        .expect("running GT")
                        .retain_cpu_vram_clear(object.clone(), epoch, narf_time::monotonic_ns())
                    {
                        Ok(lease) => break lease,
                        Err(GtError::Busy) => {}
                        Err(GtError::Scheduling(
                            crate::intel_gpu_guc_sched::SchedulingError::Slpc(
                                crate::intel_gpu_slpc::SlpcError::Busy,
                            ),
                        )) => {}
                        Err(_) => return Err(narf_filesystem::FsError::NoDevice),
                    }
                    if narf_time::monotonic_ns() >= reserve_deadline {
                        return Err(narf_filesystem::FsError::WouldBlock);
                    }
                    drop(state);
                    narf_scheduler::yield_now().await;
                    narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant())
                        .await;
                    state = owner.state.lock().await;
                };
                if let Some(lease) = &lease {
                    // This independent task owns the actual PM reference,
                    // even if the ioctl future is dropped between chunks.
                    awake
                        .take()
                        .expect("CPU clear PM hold")
                        .until(lease.completion());
                }
                let mut clear_deadline = narf_time::monotonic_ns().saturating_add(100_000_000);
                loop {
                    // An old caller must not close a recovered backend after
                    // yielding across reset into a different user epoch.
                    if owner.user_epoch.load(Ordering::Acquire) != epoch {
                        return Err(narf_filesystem::FsError::NoDevice);
                    }
                    let access = state
                        .gt
                        .as_ref()
                        .ok_or(narf_filesystem::FsError::NoDevice)?
                        .vram_access(epoch);
                    if matches!(access, Err(GtError::Busy)) {
                        if narf_time::monotonic_ns() >= clear_deadline {
                            return Err(narf_filesystem::FsError::WouldBlock);
                        }
                        drop(state);
                        narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant())
                            .await;
                        state = owner.state.lock().await;
                        continue;
                    }
                    if state.phase != Phase::Running
                        || owner.suspended.load(Ordering::Acquire)
                        || narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                            != Ok(Some(narf_bus::pci::PciPowerState::D0))
                        || !state.gt.as_ref().is_some_and(|gt| {
                            access.is_ok() && gt.vram_layout() == Some(pool.layout)
                        })
                    {
                        if owner.pending.smallbar {
                            if let Some(gt) = state.gt.as_mut() {
                                let _ = gt.poll_with_access(narf_time::monotonic_ns(), || false);
                            }
                        }
                        owner.close_controls();
                        owner.close_user_epoch();
                        return Err(narf_filesystem::FsError::NoDevice);
                    }
                    if let Some(fence) = owner
                        .pending
                        .cap
                        .invoke(ClearVramChunk(&mut clear))
                        .map_err(|_| narf_filesystem::FsError::NoDevice)?
                    {
                        let Some(lease) = &lease else {
                            return Ok(fence);
                        };
                        // End CPU writes before permitting the owner to post
                        // this transaction's fresh invalidation. Cancellation
                        // during an earlier chunk instead requests abandonment
                        // through the retained lease's Drop flag.
                        lease.ready();
                        let ticket = lease.id();
                        let deadline = narf_time::monotonic_ns().saturating_add(100_000_000);
                        loop {
                            if owner.user_epoch.load(Ordering::Acquire) != epoch {
                                return Err(narf_filesystem::FsError::NoDevice);
                            }
                            let access = state
                                .gt
                                .as_ref()
                                .ok_or(narf_filesystem::FsError::NoDevice)?
                                .vram_access(epoch);
                            if matches!(access, Err(GtError::Busy)) {
                                if narf_time::monotonic_ns() >= deadline {
                                    return Err(narf_filesystem::FsError::WouldBlock);
                                }
                                drop(state);
                                narf_time::SleepUntil::new(
                                    narf_time::Deadline::after_us(50).as_instant(),
                                )
                                .await;
                                state = owner.state.lock().await;
                                continue;
                            }
                            if state.phase != Phase::Running
                                || owner.suspended.load(Ordering::Acquire)
                                || narf_bus::pci::power_state(
                                    &owner.pending.cap,
                                    &owner.pending.device,
                                ) != Ok(Some(narf_bus::pci::PciPowerState::D0))
                                || !state.gt.as_ref().is_some_and(|gt| {
                                    access.is_ok() && gt.vram_layout() == Some(pool.layout)
                                })
                            {
                                if owner.pending.smallbar {
                                    if let Some(gt) = state.gt.as_mut() {
                                        let _ = gt
                                            .poll_with_access(narf_time::monotonic_ns(), || false);
                                    }
                                }
                                owner.close_controls();
                                owner.close_user_epoch();
                                return Err(narf_filesystem::FsError::NoDevice);
                            }
                            let now = narf_time::monotonic_ns();
                            let gt = state.gt.as_mut().expect("running GT");
                            let progress = gt.poll_with_access(now, || {
                                narf_bus::pci::power_state(
                                    &owner.pending.cap,
                                    &owner.pending.device,
                                ) == Ok(Some(narf_bus::pci::PciPowerState::D0))
                            });
                            if matches!(progress, core::task::Poll::Ready(Err(_))) {
                                if owner.pending.smallbar {
                                    if let Some(gt) = state.gt.as_mut() {
                                        let _ = gt
                                            .poll_with_access(narf_time::monotonic_ns(), || false);
                                    }
                                }
                                owner.close_controls();
                                owner.close_user_epoch();
                                return Err(narf_filesystem::FsError::NoDevice);
                            }
                            match gt.vram_flush_done(epoch, ticket) {
                                Ok(true) => return Ok(fence),
                                Ok(false) => {}
                                Err(_) => return Err(narf_filesystem::FsError::NoDevice),
                            }
                            if now >= deadline {
                                return Err(narf_filesystem::FsError::NoDevice);
                            }
                            drop(state);
                            narf_scheduler::yield_now().await;
                            narf_time::SleepUntil::new(
                                narf_time::Deadline::after_us(50).as_instant(),
                            )
                            .await;
                            state = owner.state.lock().await;
                        }
                    }
                    clear_deadline = narf_time::monotonic_ns().saturating_add(100_000_000);
                    // Keep the PM hold/private reservation, but let the GT
                    // worker service jobs between bounded CPU chunks. A reset
                    // or suspend during the yield fails the next fresh proof.
                    drop(state);
                    narf_scheduler::yield_now().await;
                    state = owner.state.lock().await;
                }
            }
            let gt = state
                .gt
                .as_mut()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let result = gt.clear_vram(narf_time::monotonic_ns(), object, epoch);
            if gt.state() == GtState::Lost {
                owner.close_controls();
                owner.close_user_epoch();
            }
            result.map_err(|_| crate::intel_gpu_user::io_error())
        })
    }
    fn publish_vram<'a>(
        &'a self,
        epoch: u64,
        pool: Arc<crate::intel_gpu_vram::Vram>,
        object: Arc<crate::intel_gpu_gem::GemObject>,
        fence: Arc<CompletionFence>,
        publish: crate::intel_gpu_user::VramPublish<'a>,
    ) -> narf_filesystem::FsFuture<'a, ()> {
        Box::pin(async move {
            use narf_filesystem::FsError;
            let owner = self.owner.upgrade().ok_or(FsError::NoDevice)?;
            let _awake = Awake::take(&owner).await?;
            let mut state = owner.lock_running().await;
            // A stale request never closes a newer recovered publication.
            if epoch == 0 || owner.user_epoch.load(Ordering::Acquire) != epoch {
                return Err(FsError::NoDevice);
            }
            let mut failed = false;
            let result = {
                let mut current = || {
                    let valid = owner.pending.smallbar
                        && state.phase == Phase::Running
                        && !owner.suspended.load(Ordering::Acquire)
                        && owner.user_epoch.load(Ordering::Acquire) == epoch
                        && crate::drm_registry::DrmCard::intel_vram(&*owner.pending.card)
                            .is_some_and(|owned| Arc::ptr_eq(&owned, &pool))
                        && object.in_vram_pool(&pool)
                        && object.initialization_complete(&fence)
                        && owner.pending.window.current()
                        && state
                            .gt
                            .as_ref()
                            .is_some_and(|gt| gt.vram_layout() == Some(pool.layout));
                    if !valid {
                        failed = true;
                        return Err(FsError::NoDevice);
                    }
                    let access = state.gt.as_ref().expect("checked GT").vram_access(epoch);
                    match access {
                        Ok(()) => Ok(()),
                        Err(GtError::Busy) => Err(FsError::WouldBlock),
                        Err(_) => {
                            failed = true;
                            Err(FsError::NoDevice)
                        }
                    }
                };
                match current() {
                    Ok(()) => publish(&mut current),
                    Err(error) => Err(error),
                }
            };
            if failed && owner.user_epoch.load(Ordering::Acquire) == epoch {
                owner.close_controls();
                owner.close_user_epoch();
                if let Some(gt) = state.gt.as_mut() {
                    let _ = gt.poll_with_access(narf_time::monotonic_ns(), || false);
                }
            }
            result
        })
    }
    fn copy_objects(
        &self,
        request: crate::intel_gpu_exec::copy::CopyRequest,
        epoch: u64,
    ) -> narf_filesystem::FsFuture<'_, Arc<CompletionFence>> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let awake = Awake::take(&owner).await?;
            let mut state = owner.lock_running().await;
            if state.phase != Phase::Running
                || epoch == 0
                || owner.user_epoch.load(Ordering::Acquire) != epoch
                || owner.suspended.load(Ordering::Acquire)
                || narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                    != Ok(Some(narf_bus::pci::PciPowerState::D0))
            {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            let pool = crate::drm_registry::DrmCard::intel_vram(&*owner.pending.card);
            if let Some(pool) = pool.as_ref().filter(|pool| pool.smallbar_enabled()) {
                match pool.smallbar_access(&owner.pending.window) {
                    Ok(()) => {}
                    Err(crate::intel_gpu_gt::lnl::Error::Busy) => {
                        return Err(narf_filesystem::FsError::WouldBlock);
                    }
                    Err(_) => {
                        owner.close_controls();
                        owner.close_user_epoch();
                        if let Some(gt) = state.gt.as_mut() {
                            let _ = gt.poll_with_access(narf_time::monotonic_ns(), || false);
                        }
                        return Err(narf_filesystem::FsError::NoDevice);
                    }
                }
            }
            let gt = state
                .gt
                .as_mut()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let result = gt.copy_objects(narf_time::monotonic_ns(), request, epoch, pool.as_ref());
            if owner.pending.smallbar
                && matches!(
                    result,
                    Err(GtError::State
                        | GtError::Unavailable
                        | GtError::WakeLost
                        | GtError::WakeTimeout)
                )
            {
                let _ = gt.poll_with_access(narf_time::monotonic_ns(), || false);
            }
            if gt.state() == GtState::Lost {
                owner.close_controls();
                owner.close_user_epoch();
            }
            match result {
                Ok(fence) => {
                    // No await separates hardware ownership from the PM hold.
                    awake.until(fence.clone());
                    Ok(fence)
                }
                Err(GtError::Busy) => Err(narf_filesystem::FsError::WouldBlock),
                Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Residency(error),
                )) => Err(error),
                Err(GtError::Scheduling(
                    crate::intel_gpu_guc_sched::SchedulingError::Busy
                    | crate::intel_gpu_guc_sched::SchedulingError::Full,
                )) => Err(narf_filesystem::FsError::WouldBlock),
                Err(_) => Err(narf_filesystem::FsError::NoDevice),
            }
        })
    }
    fn power_controls(&self) -> Option<Arc<crate::intel_gpu_power_controls::PowerControls>> {
        Some(self.power_controls.clone())
    }
    fn native_xe(&self) -> bool {
        // Fixed-mode KMS becomes usable at probe, before this GT has even
        // observed its two firmware frames. Advertise Mesa submission on
        // that route only after the live engine has passed the normal probes.
        self.owner.upgrade().is_some_and(|owner| {
            !matches!(
                owner.pending.display,
                DisplayOwner::Firmware(_) | DisplayOwner::NovaLake
            ) || self.epoch.load(Ordering::Acquire) != 0
        })
    }
    fn display_preserving(&self) -> bool {
        self.owner.upgrade().is_some_and(|owner| {
            lnl_profile(
                self.platform,
                matches!(owner.pending.display, DisplayOwner::LunarLake),
                owner.pending.mode.is_some(),
            ) == Some(LnlProfile::DisplayPreserving)
                || (matches!(owner.pending.display, DisplayOwner::PantherLake)
                    && ptl_profile(self.platform, true, owner.pending.mode.is_some())
                        == Some(LnlProfile::DisplayPreserving))
                || (matches!(owner.pending.display, DisplayOwner::NovaLakeOwned)
                    && nvl_profile(self.platform, true, owner.pending.mode.is_some())
                        == Some(LnlProfile::DisplayPreserving))
        })
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        *self.facts.lock()
    }
    fn engine_cycles(
        &self,
        engine: crate::intel_gpu_engine::Engine,
        clock: i32,
    ) -> narf_filesystem::FsFuture<'_, crate::intel_gpu_timestamp::EngineCycles> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let _awake = Awake::take(&owner).await?;
            let mut state = owner.lock_running().await;
            if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            let gt = state
                .gt
                .as_mut()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let result = gt.engine_cycles(engine, clock);
            if gt.state() == GtState::Lost {
                owner.close_controls();
                owner.close_user_epoch();
            }
            result.map_err(|error| match error {
                GtError::Busy => narf_filesystem::FsError::WouldBlock,
                GtError::State => narf_filesystem::FsError::NoDevice,
                _ => crate::intel_gpu_user::io_error(),
            })
        })
    }
    fn media_engine_cycles(
        &self,
        engine: crate::intel_gpu_engine::Engine,
        clock: i32,
    ) -> narf_filesystem::FsFuture<'_, crate::intel_gpu_timestamp::EngineCycles> {
        Box::pin(async move {
            use narf_filesystem::FsError;
            let owner = self.owner.upgrade().ok_or(FsError::NoDevice)?;
            let _awake = Awake::take(&owner).await?;
            let mut state = owner.lock_running().await;
            if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
                return Err(FsError::NoDevice);
            }
            // GT1 is sampled only while published beside a live GT0 epoch.
            if self.epoch.load(Ordering::Acquire) == 0 {
                return Err(FsError::NoDevice);
            }
            let guc = state.media_guc.as_mut().ok_or(FsError::NoDevice)?;
            let result = guc.engine_cycles(narf_time::monotonic_ns(), engine, clock);
            if guc.publication().is_none() {
                // A lost media GuC unpublishes GT1 before its verified stop.
                *owner.user_media.lock() = None;
            }
            result.map_err(|error| match error {
                GtError::Busy => FsError::WouldBlock,
                GtError::State => FsError::NoDevice,
                _ => crate::intel_gpu_user::io_error(),
            })
        })
    }
    fn pxp(&self) -> Option<Arc<crate::intel_gpu_gt::media::pxp::Pxp>> {
        self.owner.upgrade()?.user_pxp.lock().clone()
    }
    fn pxp_wakeref(&self) -> narf_filesystem::FsFuture<'_, Box<dyn core::any::Any + Send>> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let awake = owner.pxp_wakeref().await?;
            Ok(Box::new(awake) as Box<dyn core::any::Any + Send>)
        })
    }
    fn media_gt(&self) -> Option<crate::intel_gpu_user::MediaGtStatus> {
        // GT1 is only addressable beside a live GT0 user epoch.
        if self.epoch.load(Ordering::Acquire) == 0 {
            return None;
        }
        *self.media.lock()
    }
    fn media_gt_slpc_status(&self) -> Option<crate::intel_gpu_slpc::Status> {
        if self.epoch.load(Ordering::Acquire) == 0 {
            return None;
        }
        let owner = self.owner.upgrade()?;
        let state = owner.state.try_lock()?;
        state.media_guc.as_ref().and_then(|guc| guc.slpc_status())
    }
    fn media_gt_rc6_residency_ms(&self) -> Option<u64> {
        if self.epoch.load(Ordering::Acquire) == 0 {
            return None;
        }
        let owner = self.owner.upgrade()?;
        if owner.suspended.load(Ordering::Acquire) {
            return None;
        }
        let state = owner.state.try_lock()?;
        if state.phase != Phase::Running {
            return None;
        }
        state
            .media_guc
            .as_ref()
            .and_then(|guc| guc.mc6_residency_ms())
    }
    fn media_gt_act_freq_mhz(&self) -> Option<u32> {
        if self.epoch.load(Ordering::Acquire) == 0 {
            return None;
        }
        let owner = self.owner.upgrade()?;
        if owner.suspended.load(Ordering::Acquire) {
            return None;
        }
        let state = owner.state.try_lock()?;
        if state.phase != Phase::Running {
            return None;
        }
        state.media_guc.as_ref().and_then(|guc| guc.act_freq_mhz())
    }
    fn main_gt_slpc_status(&self) -> Option<crate::intel_gpu_slpc::Status> {
        if self.epoch.load(Ordering::Acquire) == 0 {
            return None;
        }
        let owner = self.owner.upgrade()?;
        let state = owner.state.try_lock()?;
        state.gt.as_ref().and_then(|gt| gt.slpc_status())
    }
    fn main_gt_rc6_residency_ms(&self) -> Option<u64> {
        if self.epoch.load(Ordering::Acquire) == 0 {
            return None;
        }
        let owner = self.owner.upgrade()?;
        if owner.suspended.load(Ordering::Acquire) {
            return None;
        }
        let state = owner.state.try_lock()?;
        if state.phase != Phase::Running {
            return None;
        }
        state.gt.as_ref()?;
        let raw = owner
            .pending
            .window
            .read32(crate::intel_gpu_rc6::GEN6_GT_GFX_RC6);
        (raw != u32::MAX).then_some((u64::from(raw) * 1280) / 1_000_000)
    }
    fn main_gt_act_freq_mhz(&self) -> Option<u32> {
        if self.epoch.load(Ordering::Acquire) == 0 {
            return None;
        }
        let owner = self.owner.upgrade()?;
        if owner.suspended.load(Ordering::Acquire) {
            return None;
        }
        let state = owner.state.try_lock()?;
        if state.phase != Phase::Running {
            return None;
        }
        state.gt.as_ref()?;
        let raw = if self.platform.is_dg2() || self.platform.is_gen12() {
            let rpstat = owner.pending.window.read32(0x1381b4);
            if rpstat == u32::MAX {
                return None;
            }
            (rpstat >> 11) & 0x1ff
        } else {
            let wp1 = owner
                .pending
                .window
                .read32(crate::intel_gpu_gt::media::MTL_MIRROR_TARGET_WP1);
            if wp1 == u32::MAX {
                return None;
            }
            wp1 & 0x1ff
        };
        Some(crate::intel_gpu_slpc::decode(raw))
    }
    fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        let epoch = self.epoch.load(Ordering::Acquire);
        let version = self.version.load(Ordering::Relaxed);
        (epoch != 0).then_some(crate::intel_gpu_user::UserStatus {
            epoch,
            platform: self.platform,
            submission_version: ((version >> 16) as u8, (version >> 8) as u8, version as u8),
            engines: crate::intel_gpu_engine::EngineSet::from_bits(
                self.engines.load(Ordering::Acquire),
            ),
        })
    }
    fn submit<'a>(
        &'a self,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
    ) -> narf_filesystem::FsFuture<'a, Arc<CompletionFence>> {
        Box::pin(async move {
            self.submit_request(context, batch, None)
                .await
                .map_err(|error| match error {
                    crate::intel_gpu_user::OutputError::Io(error) => error,
                    crate::intel_gpu_user::OutputError::Install(_) => {
                        crate::intel_gpu_user::io_error()
                    }
                })
        })
    }

    fn submit_with_output<'a>(
        &'a self,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: crate::intel_gpu_user::UserOutput<'a>,
    ) -> crate::intel_gpu_user::OutputFuture<'a> {
        Box::pin(async move { self.submit_request(context, batch, Some(&output)).await })
    }
}

impl Backend {
    async fn submit_request(
        &self,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: Option<&crate::intel_gpu_user::UserOutput<'_>>,
    ) -> Result<Arc<CompletionFence>, crate::intel_gpu_user::OutputError> {
        use crate::intel_gpu_user::OutputError;
        let owner = self
            .owner
            .upgrade()
            .ok_or(narf_filesystem::FsError::NoDevice)?;
        let awake = Awake::take(&owner).await?;
        let mut state = owner.lock_running().await;
        if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
            return Err(narf_filesystem::FsError::NoDevice.into());
        }
        if owner.pending.smallbar {
            let access = crate::drm_registry::DrmCard::intel_vram(&*owner.pending.card)
                .ok_or(narf_filesystem::FsError::NoDevice)?
                .smallbar_access(&owner.pending.window);
            match access {
                Ok(()) => {}
                Err(crate::intel_gpu_gt::lnl::Error::Busy) => {
                    return Err(narf_filesystem::FsError::WouldBlock.into());
                }
                Err(_) => {
                    owner.close_controls();
                    owner.close_user_epoch();
                    if let Some(gt) = state.gt.as_mut() {
                        let _ = gt.poll_with_access(narf_time::monotonic_ns(), || false);
                    }
                    return Err(narf_filesystem::FsError::NoDevice.into());
                }
            }
        }
        let result = if crate::intel_gpu_gt::media::profile_eligible(self.platform)
            && context.engine().is_media()
        {
            // VCS/VECS live on the standalone media GT (gt_id 1): submit to
            // its GuC under GT1's epoch. An unpublished GT1 has no engine.
            let guc = state
                .media_guc
                .as_mut()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let epoch = guc
                .publication()
                .ok_or(narf_filesystem::FsError::NoDevice)?
                .epoch;
            context.check_epoch(epoch)?;
            let result = guc.submit_user(narf_time::monotonic_ns(), context, batch, output);
            if guc.publication().is_none() {
                // A lost media GuC unpublishes GT1 before its verified stop.
                *owner.user_media.lock() = None;
            }
            result
        } else {
            let gt = state
                .gt
                .as_mut()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let epoch = gt.user_epoch().ok_or(narf_filesystem::FsError::NoDevice)?;
            context.check_epoch(epoch)?;
            let result = match output {
                Some(output) => gt.submit_user_batch_with_output(
                    narf_time::monotonic_ns(),
                    context,
                    batch,
                    output,
                ),
                None => gt.submit_user_batch(narf_time::monotonic_ns(), context, batch),
            };
            if gt.state() == GtState::Lost {
                owner.close_controls();
                owner.close_user_epoch();
            }
            result
        };
        if let Ok((_, fence)) = &result {
            awake.until(fence.clone());
        }
        result.map(|(_, fence)| fence).map_err(|error| match error {
            GtError::Scheduling(crate::intel_gpu_guc_sched::SchedulingError::Residency(error)) => {
                OutputError::Io(error)
            }
            GtError::Scheduling(crate::intel_gpu_guc_sched::SchedulingError::Output(error)) => {
                OutputError::Install(error)
            }
            GtError::Busy => OutputError::Io(narf_filesystem::FsError::WouldBlock),
            GtError::Scheduling(
                crate::intel_gpu_guc_sched::SchedulingError::Busy
                | crate::intel_gpu_guc_sched::SchedulingError::Full,
            ) => OutputError::Io(narf_filesystem::FsError::WouldBlock),
            _ => OutputError::Io(crate::intel_gpu_user::io_error()),
        })
    }
}

/// Runtime-PM callbacks, bound to the owner once it exists. Until then (and
/// after the owner is gone) suspension is refused and resume is a no-op.
struct PmOps(IrqSafeSpinLock<Weak<Owner>>);
impl RuntimePmOps for PmOps {
    fn runtime_suspend(&self) -> RpmFuture<'_> {
        let owner = self.0.lock().upgrade();
        Box::pin(async move {
            match owner {
                Some(owner) => owner.park().await,
                None => Err(RpmError::Busy),
            }
        })
    }
    fn runtime_resume(&self) -> RpmFuture<'_> {
        let owner = self.0.lock().upgrade();
        Box::pin(async move {
            if let Some(owner) = owner {
                owner.unpark().await;
            }
            Ok(())
        })
    }
}

/// Linux xe's default autosuspend delay.
const AUTOSUSPEND_MS: i32 = 1000;

/// One bounded private BAR write under current PCI capability invocation.
struct ClearVramChunk<'a>(&'a mut crate::intel_gpu_gem::CpuVramClear);
impl narf_capabilities::CapOp<BusDeviceCap, Write> for ClearVramChunk<'_> {
    type Output = Option<Arc<CompletionFence>>;
    fn execute(
        self,
        _: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        // SAFETY: private caller retains Awake and the GT reset mutex and
        // rechecks D0/epoch/wake before every at-most64KiB chunk. invoke()
        // validates the current PCI capability for the actual BAR stores.
        Ok(unsafe { self.0.clear_next() })
    }
}

/// A runtime-PM usage reference: the function stays in D0 until it drops.
struct Awake(Arc<narf_power::runtime_pm::RuntimePmDevice>);
impl Awake {
    async fn take(owner: &Owner) -> Result<Self, narf_filesystem::FsError> {
        let device = owner.pm.device.clone();
        if device.resume_and_get().await.is_err() {
            let _ = device.put_autosuspend();
            return Err(narf_filesystem::FsError::NoDevice);
        }
        Ok(Self(device))
    }
    /// Release when `fence` reaches a terminal state, not at ioctl return.
    fn until(self, fence: Arc<CompletionFence>) {
        narf_scheduler::spawn(async move {
            let _ = fence.wait().await;
            drop(self);
        });
    }
}
impl Drop for Awake {
    fn drop(&mut self) {
        self.0.mark_last_busy();
        let _ = self.0.put_autosuspend();
    }
}

/// Local memory closed to the CPU for a runtime suspend: kernel BAR access
/// refused and every user mapping of the BAR window revoked. Dropping it
/// ends the user revocation, then reopens kernel access.
struct VramCpuRevocation {
    pool: Arc<crate::intel_gpu_vram::Vram>,
    revocation: Option<narf_filesystem::mmap_relocation::DeviceFrameRevocation>,
}
impl Drop for VramCpuRevocation {
    fn drop(&mut self) {
        drop(self.revocation.take());
        self.pool.open_cpu_access();
    }
}

/// `__xe_bo_cpu_fault` for a revoked VRAM mapping: take a runtime-PM
/// reference, which resumes the function, and wait until the resumed GT is
/// published running; that publication drops the revocation first, so the
/// retried access maps the same frame. A failed resume is `Bus` (SIGBUS),
/// as xe reports a lost device.
struct VramRefault(Weak<Owner>);
impl narf_filesystem::mmap_relocation::DeviceFrameRefault for VramRefault {
    fn refault(
        &self,
        _phys: narf_memory::PhysAddr,
    ) -> narf_filesystem::mmap_relocation::DeviceRefaultFuture {
        let owner = self.0.clone();
        Box::pin(async move {
            use narf_filesystem::mmap_relocation::DeviceRefaultError;
            let owner = owner.upgrade().ok_or(DeviceRefaultError::Bus)?;
            owner
                .vram_wakeref()
                .await
                .map(drop)
                .map_err(|_| DeviceRefaultError::Bus)
        })
    }
}

static PENDING: IrqSafeSpinLock<Vec<Pending>> = IrqSafeSpinLock::new(Vec::new());
static OWNERS: IrqSafeSpinLock<Vec<Arc<Owner>>> = IrqSafeSpinLock::new(Vec::new());

/// The PCI function behind DRM card `card`, when a GT owner (started or
/// still pending) holds it: the provider or client of a cross-device dma-buf
/// attachment's P2P distance (`crate::intel_gpu_prime`).
pub(crate) fn pci_function(card: u32) -> Option<BusDevice> {
    if let Some(device) = OWNERS
        .lock()
        .iter()
        .find(|owner| owner.pending.index == card)
        .map(|owner| owner.pending.device)
    {
        return Some(device);
    }
    PENDING
        .lock()
        .iter()
        .find(|pending| pending.index == card)
        .map(|pending| pending.device)
}

/// Probe installs only identity and authority. Late spawns survive executor
/// startup; firmware scanning completes before these tasks start polling.
pub(crate) fn install(
    index: u32,
    card: Arc<IntelGpuCard>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: narf_bus::bar::MmioRegion,
    mode: Option<crate::intel_gpu_modeset::Mode>,
    firmware: Option<crate::intel_gpu::FirmwareRenderHandoff>,
) -> bool {
    install_profile(
        index,
        card,
        device,
        cap,
        bar,
        mode,
        firmware.map_or(DisplayOwner::Standard, DisplayOwner::Firmware),
    )
}

/// The Lunar Lake display-20 route's GT owner: the display-preserving
/// profile beside the route's lit panel `mode`. Refused for anything that is
/// not Lunar Lake with a lit mode.
pub(crate) fn install_lnl_display(
    index: u32,
    card: Arc<IntelGpuCard>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: narf_bus::bar::MmioRegion,
    mode: Option<crate::intel_gpu_modeset::Mode>,
) -> bool {
    let profile = GtPlatform::from_pci(device.id.vendor, device.id.device)
        .and_then(|platform| lnl_profile(platform, true, mode.is_some()));
    if profile != Some(LnlProfile::DisplayPreserving) {
        return false;
    }
    install_profile(index, card, device, cap, bar, mode, DisplayOwner::LunarLake)
}

/// The Panther Lake display-30 route's GT owner: the display-preserving
/// profile beside the route's lit panel `mode`. Refused for anything that is
/// not Panther Lake with a lit mode.
pub(crate) fn install_ptl_display(
    index: u32,
    card: Arc<IntelGpuCard>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: narf_bus::bar::MmioRegion,
    mode: Option<crate::intel_gpu_modeset::Mode>,
) -> bool {
    let profile = GtPlatform::from_pci(device.id.vendor, device.id.device)
        .and_then(|platform| ptl_profile(platform, true, mode.is_some()));
    if profile != Some(LnlProfile::DisplayPreserving) {
        return false;
    }
    install_profile(
        index,
        card,
        device,
        cap,
        bar,
        mode,
        DisplayOwner::PantherLake,
    )
}

/// The Nova Lake-S display-35 route's GT owner after the owned takeover:
/// with the owned console (`owned`), the display-preserving profile beside
/// the panel's `mode`, admitting system suspend; with the firmware surface
/// retained, the firmware route's owner. Refused for anything that is not
/// Nova Lake-S with a lit mode.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install_nvl_display(
    index: u32,
    card: Arc<IntelGpuCard>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: narf_bus::bar::MmioRegion,
    mode: Option<crate::intel_gpu_modeset::Mode>,
    owned: bool,
) -> bool {
    let profile = GtPlatform::from_pci(device.id.vendor, device.id.device)
        .and_then(|platform| nvl_profile(platform, true, mode.is_some()));
    if profile != Some(LnlProfile::DisplayPreserving) {
        return false;
    }
    if owned {
        install_profile(
            index,
            card,
            device,
            cap,
            bar,
            mode,
            DisplayOwner::NovaLakeOwned,
        )
    } else {
        install_profile(index, card, device, cap, bar, None, DisplayOwner::NovaLake)
    }
}

#[allow(clippy::too_many_arguments)]
fn install_profile(
    index: u32,
    card: Arc<IntelGpuCard>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: narf_bus::bar::MmioRegion,
    mode: Option<crate::intel_gpu_modeset::Mode>,
    display: DisplayOwner,
) -> bool {
    // Gen9/Gen11 run on execlists, as Linux does by default: i915 has no GuC
    // submission below graphics 11 and does not enable it below 12.
    if GtPlatform::from_pci(device.id.vendor, device.id.device)
        .and_then(crate::intel_gpu_legacy_gt::LegacyGt::for_platform)
        .is_some()
    {
        let config = |offset| narf_bus::pci::read_config32(&cap, &device, offset).ok();
        let revision = config(0x08).map_or(0, |v| v as u8);
        // INTEL_BSM and SNB_GMCH_CTRL: the DSM Gen9 LP's BIOS RC6 setup uses.
        let dsm = config(0x5c)
            .zip(config(0x50))
            .and_then(|(bsm, gmch)| crate::intel_gpu_legacy_power::gen9_dsm(bsm, gmch));
        return crate::intel_gpu_legacy_owner::install(index, card, &device, revision, dsm, bar);
    }
    // A graphics 9 or 11 part without an execlists profile never takes the
    // GuC start below, though it has a GuC blob: i915 submits through the
    // GuC only from graphics 12 (`uc_expand_default_options`).
    if matches!(
        GtPlatform::from_pci(device.id.vendor, device.id.device),
        Some(GtPlatform::Gen9(_) | GtPlatform::Gen11(_))
    ) {
        log(
            index,
            "no execlists profile for this graphics 9 part; GT not started",
        );
        return false;
    }
    if GtPlatform::from_pci(device.id.vendor, device.id.device)
        .and_then(GtPlatform::guc)
        .is_none()
    {
        return false;
    }
    if crate::intel_gpu_gt::ownership::claim_guc(device.addr, bar).is_err() {
        log(
            index,
            "GT already owned or conflicting BAR; GuC not installed",
        );
        return false;
    }
    let smallbar = GtPlatform::from_pci(device.id.vendor, device.id.device)
        == Some(GtPlatform::Battlemage)
        && crate::intel_gpu_gt::smallbar::requested(narf_boot::args());
    let window = if smallbar {
        AuthorizedWindow::for_bmg_device(bar, cap, device, card.local_bar())
    } else {
        AuthorizedWindow::for_device(bar, cap, device)
    };
    PENDING.lock().push(Pending {
        index,
        card,
        device,
        cap,
        bar,
        mode,
        smallbar,
        display,
        window,
        display_lit: false,
    });
    true
}

pub(crate) fn start_pending() {
    crate::intel_gpu_legacy_owner::start_pending();
    let pending = core::mem::take(&mut *PENDING.lock());
    for p in pending {
        let name = alloc::format!("intel-gt-{}", p.index);
        let ops = Arc::new(PmOps(IrqSafeSpinLock::new(Weak::new())));
        // The probe and forbid references keep the function in D0 until a
        // running, eligible GT explicitly allows autosuspend. No platform
        // power provider exists, so the PCI layer stops at D3hot (`d3cold`).
        let pm = match narf_power::runtime_pm_pci::register_pci_device(
            &name,
            p.cap,
            p.device,
            ops.clone(),
            None,
            Arc::new(SchedulerEnv),
        ) {
            Ok(node) => node,
            Err(_) => {
                log(p.index, "runtime-PM registration failed; GT not started");
                continue;
            }
        };
        let hwmon = crate::intel_gpu_hwmon::Monitor::register(
            p.index,
            GtPlatform::from_pci(p.device.id.vendor, p.device.id.device)
                .expect("admitted platform"),
            p.bar.len,
        );
        let ccs_control = crate::intel_gpu_ccs_control::Control::new(p.index);
        let coredump = crate::intel_gpu_error::coredump::arm(p.index);
        let user_epoch = Arc::new(AtomicU64::new(0));
        let reset_publication = Arc::new(recovery::Publication::new(
            GtPlatform::from_pci(p.device.id.vendor, p.device.id.device)
                .expect("admitted platform"),
        ));
        let profile = display_rpm::profile(
            GtPlatform::from_pci(p.device.id.vendor, p.device.id.device),
            p.mode.is_some() || p.display_lit,
            p.smallbar,
        );
        // Every pipe already reported lit (KMS install's owned Pipe A) holds
        // its display wakeref from here on: a lit panel keeps the function
        // active even once autosuspend is armed.
        if profile == Ok(display_rpm::Profile::Display) {
            // The owned panel mode is a lit Pipe A whether or not KMS
            // install reported it (the report is idempotent).
            display_rpm::pipe_lit(p.bar.phys.raw(), 0);
            display_rpm::bind(p.bar.phys.raw(), pm.device.clone());
        }
        let runtime_power = crate::intel_gpu_power_controls::runtime::Control::register(
            p.index,
            pm.device.clone(),
            user_epoch.clone(),
            profile.is_ok(),
        );
        let owner = Arc::new(Owner {
            pending: p,
            pm,
            profile,
            autosuspend: AtomicBool::new(false),
            system_awake: IrqSafeSpinLock::new(None),
            runtime_power,
            state: Mutex::new(State {
                coredump,
                coredump_enabled: crate::intel_gpu_error::coredump::enabled(),
                coredump_retry_ns: 0,
                irq: None,
                irq_tried: false,
                gt: None,
                firmware: None,
                huc: None,
                probe: None,
                recovery: recovery::Coordinator::new(reset_publication.clone()),
                phase: Phase::Cold,
                firmware_frame: None,
                saved: None,
                power_ready: 0,
                parked_epoch: None,
                vram_cpu: None,
                slpc_reported: false,
                ccs_mode: ccs_boot_mode(narf_boot::args()),
                lnl_flr: None,
                lnl_receipt: None,
                lnl_clients: None,
                smallbar_takeover: None,
                smallbar_authority: None,
                smallbar_grant_deadline: None,
                media: None,
                media_reported: false,
                media_guc: None,
                media_guc_tried: false,
                media_guc_reported: false,
                media_recovered: false,
                media_irq_failed: false,
                media_huc_established: false,
                media_huc_reported: false,
                gsc: None,
                gsc_reported: None,
                gsc_irq_failed: false,
                pxp: Default::default(),
                kcr_irq_failed: false,
            }),
            suspended: AtomicBool::new(false),
            user_epoch,
            reset_publication,
            log_publication: Arc::new(crate::intel_gpu_guc_log::stream::Publication::new()),
            user_version: Arc::new(AtomicU32::new(0)),
            user_engines: Arc::new(core::sync::atomic::AtomicU32::new(0)),
            user_media: Arc::new(IrqSafeSpinLock::new(None)),
            user_pxp: IrqSafeSpinLock::new(None),
            user_facts: Arc::new(IrqSafeSpinLock::new(None)),
            eu_info: IrqSafeSpinLock::new(None),
            oa_info: IrqSafeSpinLock::new(None),
            power_controls: Arc::new(crate::intel_gpu_power_controls::PowerControls::new()),
            hwmon,
            ccs_control,
        });
        *ops.0.lock() = Arc::downgrade(&owner);
        let backend = Arc::new(Backend {
            owner: Arc::downgrade(&owner),
            epoch: owner.user_epoch.clone(),
            version: owner.user_version.clone(),
            engines: owner.user_engines.clone(),
            media: owner.user_media.clone(),
            platform: GtPlatform::from_pci(
                owner.pending.device.id.vendor,
                owner.pending.device.id.device,
            )
            .expect("admitted platform"),
            facts: owner.user_facts.clone(),
            power_controls: owner.power_controls.clone(),
            ccs_control: owner.ccs_control.clone(),
        });
        if owner.pending.card.install_user_backend(backend).is_err() {
            log(
                owner.pending.index,
                "duplicate userspace backend; GT not started",
            );
            continue;
        }
        OWNERS.lock().push(owner.clone());
        if let Some(platform) = GtPlatform::from_pci(
            owner.pending.device.id.vendor,
            owner.pending.device.id.device,
        ) {
            crate::intel_gpu_guc_log::stream::register_owner(
                owner.pending.index,
                platform,
                &owner.log_publication,
            );
        }
        narf_power::device_pm::register_device_pm_ops(&name, owner.clone());
        narf_power::system_pm::register_async_system_pm(&name, owner.clone());
        narf_scheduler::spawn(async move { owner.run().await });
    }
}

fn log(index: u32, text: &str) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "intel-gt card{index}: {text}");
}

fn validate_pci(p: &Pending, mmio: &impl MmioWindow) -> Result<u8, RuntimeError> {
    let read = |off| {
        narf_bus::pci::read_config32(&p.cap, &p.device, off).map_err(|_| RuntimeError::Authority)
    };
    let revision = pci_identity(read, p.device.id.vendor, p.device.id.device)?;
    if GtPlatform::from_pci(p.device.id.vendor, p.device.id.device)
        .is_some_and(|p| p.is_headless_integrated())
    {
        let command = read(4)?;
        let low = read(0x10)?;
        if command == u32::MAX || command & 6 != 6 || low == u32::MAX || low & 1 != 0 {
            return Err(RuntimeError::Device);
        }
        let high = if low & 6 == 4 { read(0x14)? } else { 0 };
        if (u64::from(high) << 32 | u64::from(low & !15)) != p.bar.phys.raw() {
            return Err(RuntimeError::Device);
        }
    }
    let vf = mmio.read32(0x1901f8);
    if vf == u32::MAX || vf & 1 != 0 || p.bar.len < 16 * 1024 * 1024 {
        return Err(RuntimeError::Device);
    }
    if let Some(platform) = GtPlatform::from_pci(p.device.id.vendor, p.device.id.device)
        .filter(|platform| platform.is_discrete() && platform.has_display() && !p.smallbar)
    {
        validate_discrete_display(platform, mmio)?;
    }
    if narf_bus::pci::power_state(&p.cap, &p.device).ok().flatten()
        != Some(narf_bus::pci::PciPowerState::D0)
    {
        return Err(RuntimeError::Device);
    }
    Ok(revision)
}

/// Universal planes per discrete display pipe: DG1 has Display 12's six
/// sprites plus the primary plane; DG2/BMG expose four sprites plus the
/// primary. MIT intel_display_device.c:1788-1793 and the platform descriptors.
fn discrete_planes(platform: GtPlatform) -> u64 {
    if platform == GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::Dg1) {
        7
    } else {
        5
    }
}

/// Source display inventory only; no display activation. The GT owner writes
/// GGTT entries only from its 256 MiB arena up and never resets the display,
/// so a firmware-lit display may stay lit while every plane and cursor
/// fetches below the arena and no DSB runs ([`crate::intel_gpu::
/// planes_below_arena`]); the discrete KMS owner takes over from there.
fn validate_discrete_display(
    platform: GtPlatform,
    mmio: &impl MmioWindow,
) -> Result<(), RuntimeError> {
    if !platform.is_discrete() {
        return Err(RuntimeError::Device);
    }
    if !platform.has_display() {
        return Ok(());
    }
    if crate::intel_gpu::planes_below_arena(mmio, 4, discrete_planes(platform), true) {
        Ok(())
    } else {
        Err(RuntimeError::Device)
    }
}

/// Any discrete plane or cursor enabled at probe: the function keeps a lit
/// display and must stay in D0 (no runtime autosuspend).
fn discrete_display_lit(platform: GtPlatform, mmio: &impl MmioWindow) -> bool {
    use crate::intel_gpu_pipes::{Pipe, PLANE_CTL_ENABLE, PLANE_CTL_OFFSET, PLANE_PRIMARY_OFFSET};
    platform.has_display()
        && [Pipe::A, Pipe::B, Pipe::C, Pipe::D]
            .into_iter()
            .any(|pipe| {
                let base = pipe.base();
                (0..discrete_planes(platform)).any(|id| {
                    mmio.read32(base + PLANE_PRIMARY_OFFSET + id * 0x100 + PLANE_CTL_OFFSET)
                        & PLANE_CTL_ENABLE
                        != 0
                }) || mmio.read32(base + 0x80) & 0x27 != 0
            })
}

fn pci_identity(
    mut read: impl FnMut(u16) -> Result<u32, RuntimeError>,
    vendor: u16,
    device: u16,
) -> Result<u8, RuntimeError> {
    if read(0)? != (u32::from(device) << 16 | u32::from(vendor)) {
        return Err(RuntimeError::Device);
    }
    let revision = read(8)?;
    if revision == u32::MAX {
        return Err(RuntimeError::Device);
    }
    let mut off = 0x100u16;
    let mut seen = [0u16; 64];
    for count in 0..64 {
        if seen[..count].contains(&off) {
            return Err(RuntimeError::Device);
        }
        seen[count] = off;
        let header = read(off)?;
        if header == u32::MAX {
            return Err(RuntimeError::Device);
        }
        if header == 0 {
            return Ok(revision as u8);
        }
        if header as u16 == 0x10
            && (off > 0xfec || read(off + 8)? & 1 != 0 || read(off + 0x10)? & 0xffff != 0)
        {
            return Err(RuntimeError::Device);
        }
        let next = (header >> 20) as u16;
        if next == 0 {
            return Ok(revision as u8);
        }
        if !(0x100..=0xffc).contains(&next) || next % 4 != 0 {
            return Err(RuntimeError::Device);
        }
        off = next;
    }
    Err(RuntimeError::Device)
}

/// A single unambiguous boot selection is immutable for each physical owner.
/// Invalid explicit settings refuse scheduling; tokens after `--` are init args.
fn ccs_boot_mode(command_line: narf_boot::args::KernelCmdline<'_>) -> Result<u8, RuntimeError> {
    let mut selection = None;
    for token in command_line.tokens().take_while(|token| *token != "--") {
        let value = if token == "narf.intel.ccs_mode" {
            return Err(RuntimeError::Configuration);
        } else if let Some(value) = token.strip_prefix("narf.intel.ccs_mode=") {
            value
        } else {
            continue;
        };
        if selection.is_some() {
            return Err(RuntimeError::Configuration);
        }
        selection = Some(match value {
            "1" => 1,
            "2" => 2,
            "3" => 3,
            "4" => 4,
            _ => return Err(RuntimeError::Configuration),
        });
    }
    Ok(selection.unwrap_or(1))
}

/// Every advertised physical engine must retire and verify its own private
/// PPGTT store before publication. The order comes from the frozen EngineSet.
fn next_probe_engine(
    engines: crate::intel_gpu_engine::EngineSet,
    completed: crate::intel_gpu_engine::Engine,
) -> Result<Option<crate::intel_gpu_engine::Engine>, RuntimeError> {
    let at = engines
        .iter()
        .position(|engine| engine == completed)
        .ok_or(RuntimeError::State)?;
    Ok(engines.iter().nth(at + 1))
}

impl Owner {
    fn close_log_publication(&self) {
        crate::intel_gpu_guc_log::stream::close_publication(
            self.pending.index,
            &self.log_publication,
        );
    }
    fn close_user_epoch(&self) {
        self.reset_publication.withdraw();
        self.close_log_publication();
        self.user_epoch.store(0, Ordering::Release);
    }
    fn close_controls(&self) {
        self.power_controls.close();
        if let Some(hwmon) = &self.hwmon {
            hwmon.close();
        }
    }

    fn cold_start(&self, state: &mut State) -> Result<(), RuntimeError> {
        let mode = state.ccs_mode?;
        let platform =
            GtPlatform::from_pci(self.pending.device.id.vendor, self.pending.device.id.device)
                .ok_or(RuntimeError::Device)?;
        if mode != 1 && !platform.multiple_ccs() {
            return Err(RuntimeError::Configuration);
        }
        state.irq.take();
        state.irq_tried = false;
        state.recovery.cold();
        state.smallbar_grant_deadline = None;
        if state
            .gt
            .as_ref()
            .is_some_and(|gt| !matches!(gt.state(), GtState::Staged | GtState::Stopped))
        {
            return Err(RuntimeError::State);
        }
        if state.media_guc.is_some() {
            return Err(RuntimeError::State);
        }
        state.gt.take(); // only verified stopped owners can be replaced
        let p = &self.pending;
        let mmio = p.window.clone();
        let mut revision = validate_pci(p, &mmio)?;
        let platform = GtPlatform::from_pci(p.device.id.vendor, p.device.id.device)
            .ok_or(RuntimeError::Device)?;
        if let DisplayOwner::Firmware(handoff) = p.display {
            match handoff.poll(&mmio, &mut state.firmware_frame, narf_time::monotonic_ns()) {
                Some(core::task::Poll::Ready(())) => {}
                Some(core::task::Poll::Pending) => {
                    state.phase = Phase::Takeover;
                    return Ok(());
                }
                None => {
                    log(
                        p.index,
                        "firmware display ownership check failed; render engine withheld",
                    );
                    return Err(RuntimeError::Configuration);
                }
            }
        }
        // Each verified restart needs a fresh policy proof. Reusing an arena
        // after S3 would publish new PTEs using the pre-suspend PAT/MOCS state
        // before hardware initialization has re-established that state.
        let arena = if p.smallbar {
            if p.mode.is_some()
                || crate::intel_gpu_kms::display(p.index).is_some()
                || !crate::intel_gpu::lnl_boot_scanout_excluded()
                || !mmio.current()
            {
                return Err(RuntimeError::Configuration);
            }
            let local = p.card.local_bar().ok_or(RuntimeError::Configuration)?;
            if state.smallbar_authority.is_none() {
                if self.user_epoch.load(Ordering::Acquire) != 0
                    || p.card.intel_vram_used().is_some_and(|v| v != 0)
                {
                    return Err(RuntimeError::Configuration);
                }
                if state.lnl_clients.is_none() {
                    state.lnl_clients = Some(
                        crate::intel_gpu_ccs_control::takeover_clients(p.index)
                            .map_err(|_| RuntimeError::Configuration)?,
                    );
                }
                if state.smallbar_takeover.is_none() {
                    state.smallbar_takeover = Some(
                        crate::intel_gpu_gt::smallbar::Takeover::new(
                            p.device,
                            p.bar,
                            local,
                            narf_time::monotonic_ns(),
                        )
                        .map_err(RuntimeError::Takeover)?,
                    );
                }
                match state
                    .smallbar_takeover
                    .as_mut()
                    .expect("retained BMG takeover")
                    .poll(&mmio, narf_time::monotonic_ns(), || {
                        mmio.current() && crate::intel_gpu::lnl_boot_scanout_excluded()
                    }) {
                    core::task::Poll::Pending => {
                        state.phase = Phase::Takeover;
                        return Ok(());
                    }
                    core::task::Poll::Ready(result) => {
                        state.smallbar_authority = Some(result.map_err(RuntimeError::Takeover)?)
                    }
                }
                revision = validate_pci(p, &mmio)?;
            }
            let authority = state
                .smallbar_authority
                .as_ref()
                .ok_or(RuntimeError::State)?
                .clone();
            if !authority.matches(p.bar, local) {
                return Err(RuntimeError::State);
            }
            authority.current(&mmio).map_err(RuntimeError::Takeover)?;
            SharedArena::new(
                GgttArena::for_smallbar_gt(p.bar, mmio.clone(), authority)
                    .map_err(|_| RuntimeError::State)?,
            )
        } else if lnl_profile(
            platform,
            matches!(p.display, DisplayOwner::LunarLake),
            p.mode.is_some(),
        ) == Some(LnlProfile::DisplayPreserving)
        {
            // §17 10.5: never the headless driver FLR, which would reset the
            // route's lit panel. Each cold start re-admits from current
            // hardware; HardwareInit's GT-only reset precedes every PTE. The
            // boot framebuffer and any KMS display stay live, so neither the
            // headless boot-scanout exclusion nor its client gate applies.
            if !crate::intel_gpu_xe2lpd::route_owns_pipe_a() {
                return Err(RuntimeError::Configuration);
            }
            let receipt =
                crate::intel_gpu_gt::lnl::Receipt::admit_display(p.device, p.bar, &mmio, || {
                    validate_pci(p, &mmio).is_ok()
                })
                .map_err(RuntimeError::Takeover)?;
            SharedArena::new(
                GgttArena::for_lnl_gt(p.bar, p.cap, p.device, receipt)
                    .map_err(|_| RuntimeError::State)?,
            )
        } else if matches!(p.display, DisplayOwner::PantherLake)
            && ptl_profile(platform, true, p.mode.is_some()) == Some(LnlProfile::DisplayPreserving)
        {
            // The Panther Lake display-30 route: the same display-preserving
            // cold start, admitted against display 30.00.
            if !crate::intel_gpu_xe2lpd::route_owns_pipe_a() {
                return Err(RuntimeError::Configuration);
            }
            let receipt = crate::intel_gpu_gt::lnl::Receipt::admit_display_ptl(
                p.device,
                p.bar,
                &mmio,
                || validate_pci(p, &mmio).is_ok(),
            )
            .map_err(RuntimeError::Takeover)?;
            SharedArena::new(
                GgttArena::for_lnl_gt(p.bar, p.cap, p.device, receipt)
                    .map_err(|_| RuntimeError::State)?,
            )
        } else if matches!(
            p.display,
            DisplayOwner::NovaLake | DisplayOwner::NovaLakeOwned
        ) {
            // Nova Lake-S display 35 on its firmware primary or its owned
            // console: the display-preserving cold start (GT-only GuC and
            // full reset, no driver FLR), admitted while only Pipe A's
            // primary fetches. The owned route must still hold Pipe A.
            if matches!(p.display, DisplayOwner::NovaLakeOwned)
                && (nvl_profile(platform, true, p.mode.is_some())
                    != Some(LnlProfile::DisplayPreserving)
                    || !crate::intel_gpu_xe2lpd::route_owns_pipe_a())
            {
                return Err(RuntimeError::Configuration);
            }
            let receipt = crate::intel_gpu_gt::lnl::Receipt::admit_display_nvl(
                p.device,
                p.bar,
                &mmio,
                || validate_pci(p, &mmio).is_ok(),
            )
            .map_err(RuntimeError::Takeover)?;
            SharedArena::new(
                GgttArena::for_lnl_gt(p.bar, p.cap, p.device, receipt)
                    .map_err(|_| RuntimeError::State)?,
            )
        } else if matches!(
            p.display,
            DisplayOwner::LunarLake | DisplayOwner::PantherLake
        ) {
            return Err(RuntimeError::Configuration);
        } else if platform.is_headless_integrated() {
            if self.user_epoch.load(Ordering::Acquire) != 0
                || p.mode.is_some()
                || crate::intel_gpu_kms::display(p.index).is_some()
                || !crate::intel_gpu::lnl_boot_scanout_excluded()
            {
                return Err(RuntimeError::Configuration);
            }
            if state.lnl_clients.is_none() {
                state.lnl_clients = Some(
                    crate::intel_gpu_ccs_control::takeover_clients(p.index)
                        .map_err(|_| RuntimeError::Configuration)?,
                );
            }
            if state.lnl_receipt.is_none() {
                if state.lnl_flr.is_none() {
                    state.lnl_flr = Some(
                        crate::intel_gpu_gt::lnl::DriverFlr::new(
                            p.device,
                            p.bar,
                            narf_time::monotonic_ns(),
                        )
                        .map_err(RuntimeError::Takeover)?,
                    );
                }
                match state.lnl_flr.as_mut().expect("owned integrated FLR").poll(
                    &mmio,
                    narf_time::monotonic_ns(),
                    || {
                        validate_pci(p, &mmio).is_ok()
                            && crate::intel_gpu::lnl_boot_scanout_excluded()
                    },
                ) {
                    core::task::Poll::Pending => {
                        state.phase = Phase::Takeover;
                        return Ok(());
                    }
                    core::task::Poll::Ready(result) => {
                        state.lnl_receipt = Some(result.map_err(RuntimeError::Takeover)?)
                    }
                }
                // The reset invalidates every earlier sampled PCI/IP/wake fact.
                revision = validate_pci(p, &mmio)?;
            }
            let arena = GgttArena::for_lnl_gt(
                p.bar,
                p.cap,
                p.device,
                state.lnl_receipt.take().expect("fresh integrated FLR"),
            )
            .map_err(|_| RuntimeError::State)?;
            state.lnl_flr = None; // completed receipt was consumed by this fresh arena
            SharedArena::new(arena)
        } else if platform.has_sriov() {
            SharedArena::new(
                GgttArena::for_sriov_pf_gt(p.bar, mmio.clone(), platform)
                    .map_err(|_| RuntimeError::State)?,
            )
        } else {
            SharedArena::new(GgttArena::for_gt(p.bar, p.cap, platform))
        };
        if state.firmware.is_none() {
            let authority: Cap<narf_firmware::FirmwareRegistry, Read> =
                narf_firmware::trusted_loader_authority()
                    .ok_or(RuntimeError::Authority)?
                    .derive()
                    .map_err(|_| RuntimeError::Authority)?;
            state.firmware = Some(
                GuCFirmware::open_for_revision(platform, revision, &authority)
                    .map_err(RuntimeError::Firmware)?,
            );
        }
        // HuC is default-off (`narf.intel.huc=1`) and only on a primary GT
        // with a HuC profile: exact TGL, a Gen11 sub-platform (Lane 7),
        // or a Gen9 sub-platform (Gen9 Lane 7).
        // The media-GT HuC opt-in below is a separate path.
        let huc_enabled =
            crate::intel_gpu_huc::profile(platform, crate::intel_gpu_guc_boot::GuCRole::Primary)
                && crate::intel_gpu_huc::opted_in(narf_boot::args());
        if huc_enabled && state.huc.is_none() {
            let authority = narf_firmware::trusted_loader_authority()
                .ok_or(RuntimeError::Authority)?
                .derive()
                .map_err(|_| RuntimeError::Authority)?;
            state.huc = Some(
                crate::intel_gpu_huc::Firmware::open_for_revision(platform, revision, &authority)
                    .map_err(RuntimeError::Firmware)?,
            );
        }
        let config = BootConfig {
            device_id: p.device.id.device,
            revision,
            huc_upload_bytes: 0,
            uncached_mocs: platform.is_xe2().then_some(3),
        };
        let firmware = state.firmware.as_ref().expect("prepared image");
        state.gt = Some(
            if let Some(huc) = state.huc.as_ref().filter(|_| huc_enabled) {
                GuCGt::stage_hardware_with_huc(mmio, arena, firmware, huc, config)
            } else {
                GuCGt::stage_hardware(mmio, arena, firmware, config)
            }
            .map_err(RuntimeError::Gt)?,
        );
        state
            .gt
            .as_mut()
            .expect("retained GT")
            .begin(narf_time::monotonic_ns())
            .map_err(RuntimeError::Gt)?;
        state.phase = Phase::Booting;
        Ok(())
    }

    fn step(&self, state: &mut State, reconfiguration_power: bool) -> Result<(), RuntimeError> {
        if state.phase != Phase::Running {
            let retired = self.retire_media(state, narf_time::monotonic_ns());
            // A new GT0 incarnation builds a new GGTT arena over the same
            // GGTT: never while the media GuC may still translate through it.
            if retired != MediaRetire::Done
                && matches!(state.phase, Phase::Cold | Phase::Powering | Phase::Takeover)
            {
                if retired == MediaRetire::Retained {
                    log(
                        self.pending.index,
                        "media GuC stop unproven; shared GGTT retained, GT not restarted",
                    );
                    state.phase = Phase::Failed;
                }
                return Ok(());
            }
        }
        if let Some(session) = crate::intel_gpu_guc_log::stream::take_requested(self.pending.index)
        {
            let admitted = if state.phase == Phase::Running
                && !self.suspended.load(Ordering::Acquire)
                && narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
            {
                let digest = state.firmware.as_ref().map(|f| f.digest);
                match (state.gt.as_mut(), digest) {
                    (Some(gt), Some(digest))
                        if session.requested_incarnation() == gt.log_incarnation()
                            && session.requested_incarnation().is_some() =>
                    {
                        gt.attach_log_stream(
                            session.clone(),
                            self.user_epoch.load(Ordering::Acquire),
                            narf_time::monotonic_ns(),
                            digest,
                        )
                    }
                    _ => Err(narf_filesystem::FsError::NoDevice),
                }
            } else {
                Err(narf_filesystem::FsError::NoDevice)
            };
            if let Err(error) = admitted {
                session.fail(error);
            }
        }
        if state.phase == Phase::Cold {
            let current = narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                .map_err(|_| RuntimeError::Authority)?
                .ok_or(RuntimeError::Device)?;
            if current != narf_bus::pci::PciPowerState::D0 {
                narf_bus::pci::set_power_state(
                    &self.pending.cap,
                    &self.pending.device,
                    narf_bus::pci::PciPowerState::D0,
                )
                .map_err(|_| RuntimeError::Authority)?;
                state.power_ready = narf_time::monotonic_ns()
                    .checked_add(10_000_000)
                    .ok_or(RuntimeError::State)?;
                state.phase = Phase::Powering;
                return Ok(());
            }
            return self.cold_start(state);
        }
        if state.phase == Phase::Takeover {
            return self.cold_start(state);
        }
        if state.phase == Phase::Powering {
            if narf_time::monotonic_ns() < state.power_ready {
                return Ok(());
            }
            return self.cold_start(state);
        }
        if matches!(state.phase, Phase::Failed | Phase::Stopped | Phase::Parked) {
            return Ok(());
        }
        let now = narf_time::monotonic_ns();
        if state.coredump_enabled && state.coredump.is_none() && now >= state.coredump_retry_ns {
            state.coredump = crate::intel_gpu_error::coredump::arm(self.pending.index);
            state.coredump_retry_ns = now.saturating_add(1_000_000_000);
        }
        let digest = state
            .firmware
            .as_ref()
            .map_or([0; 32], |firmware| firmware.digest);
        let gt = state.gt.as_mut().ok_or(RuntimeError::State)?;
        let polled = state.recovery.poll(gt, now, || {
            narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                == Ok(Some(narf_bus::pci::PciPowerState::D0))
        });
        if let Some(report) = gt.take_error_report() {
            if let Some(buffer) = state.coredump.take() {
                gt.capture_coredump(buffer, report, narf_time::monotonic_ns(), digest, || {
                    narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                        == Ok(Some(narf_bus::pci::PciPowerState::D0))
                });
            }
            crate::intel_gpu_error::record(self.pending.index, report);
        }
        if matches!(
            polled,
            core::task::Poll::Ready(Ok(GtState::SchedulingReady))
        ) {
            gt.poll_log_stream(now, || {
                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
            })
            .map_err(RuntimeError::Gt)?;
            gt.poll_eu_stall(now, || {
                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
            });
            gt.poll_oa(now, || {
                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
            });
        }
        let current = match polled {
            core::task::Poll::Pending => return Ok(()),
            core::task::Poll::Ready(result) => result.map_err(RuntimeError::Gt)?,
        };
        match (state.phase, current) {
            (Phase::Booting, GtState::Ready) => {
                if gt.has_hwconfig() {
                    gt.begin_hwconfig(now).map_err(RuntimeError::Gt)?;
                }
                state.phase = Phase::Discovering;
            }
            (Phase::Discovering, GtState::Ready) => {
                if gt.has_hwconfig() {
                    match self.pending.card.publish_gt_hwconfig(gt) {
                        Ok(()) | Err(GtError::Busy) => {}
                        Err(e) => return Err(RuntimeError::Gt(e)),
                    }
                }
                self.pending
                    .card
                    .publish_gt_topology(gt)
                    .map_err(RuntimeError::Gt)?;
                if crate::intel_gpu_eu_stall::enabled() {
                    // Optional allocation precedes every heavy startup GGTT
                    // invalidate. No observation address is rebound while live.
                    let _ = gt.prepare_eu_stall(self.pending.index);
                }
                if crate::intel_gpu_oa::enabled() {
                    // The OA buffer is reserved under the same rule.
                    let _ = gt.prepare_oa();
                }
                if crate::intel_gpu_error::coredump::enabled() {
                    // GuC error-capture lists join the submission ADS reload.
                    let _ = gt.prepare_error_capture();
                }
                gt.begin_scheduling_with_ccs_mode(now, state.ccs_mode?)
                    .map_err(RuntimeError::Gt)?;
                state.phase = Phase::Reloading;
            }
            (Phase::Reloading, GtState::Ready) => {
                gt.begin_ct(now).map_err(RuntimeError::Gt)?;
                state.phase = Phase::Ct;
            }
            (Phase::Ct, GtState::SchedulingReady) => {
                // Optional GuC frequency/RC6 management, as xe_guc_pc_start.
                state.slpc_reported = gt.begin_slpc(now).is_err();
                if state.slpc_reported {
                    log(
                        self.pending.index,
                        "GuC SLPC not started; retaining current GT frequency policy",
                    );
                }
                let (_, completion) = gt.submit_kernel_probe(now).map_err(RuntimeError::Gt)?;
                state.probe = Some(completion);
                state.phase = Phase::Probe;
            }
            (Phase::Probe, GtState::SchedulingReady) => {
                if let Some(result) = state.probe.as_ref().expect("owned probe").result() {
                    result.map_err(|_| RuntimeError::State)?;
                    state.probe = Some(gt.begin_context_defaults(now).map_err(RuntimeError::Gt)?);
                    state.phase = Phase::Defaults;
                }
            }
            (Phase::Defaults, GtState::SchedulingReady) => {
                if let Some(result) = state.probe.as_ref().expect("owned defaults fence").result() {
                    result.map_err(|_| RuntimeError::State)?;
                    if !gt.context_defaults_ready() {
                        return Err(RuntimeError::State);
                    }
                    state
                        .recovery
                        .begin_qualification(gt, now)
                        .map_err(RuntimeError::Gt)?;
                    state.probe = None;
                    state.phase = Phase::PpgttProbe;
                }
            }
            (Phase::PpgttProbe, GtState::SchedulingReady) => {
                if state
                    .recovery
                    .advance_qualification(gt, now)
                    .map_err(RuntimeError::Gt)?
                {
                    let engines = gt.engines().ok_or(RuntimeError::State)?;
                    if let Some((epoch, previous, compute)) = state.parked_epoch {
                        if previous != engines || gt.compute_configuration() != Some(compute) {
                            return Err(RuntimeError::State);
                        }
                        gt.adopt_user_epoch(epoch).map_err(RuntimeError::Gt)?;
                    }
                    let facts = gt.device_facts().map_err(RuntimeError::Gt)?;
                    *self.user_facts.lock() = Some(facts);
                    *self.oa_info.lock() = gt.oa_device(self.pending.index, &facts);
                    *self.eu_info.lock() = gt.eu_stall_info();
                    // Before the epoch: discovery sees VRAM with the engines.
                    if !self.pending.smallbar {
                        self.pending
                            .card
                            .publish_gt_vram(gt)
                            .map_err(|_| RuntimeError::State)?;
                    }
                    state.phase = Phase::Huc;
                    let (major, minor, patch) = gt.submission_version();
                    self.user_version.store(
                        u32::from(major) << 16 | u32::from(minor) << 8 | u32::from(patch),
                        Ordering::Relaxed,
                    );
                    self.user_engines.store(
                        gt.engines().ok_or(RuntimeError::State)?.bits(),
                        Ordering::Release,
                    );
                    // Epoch publication follows an independent console
                    // recovery attempt, outside this GT mutex. A display
                    // waiter may itself still depend on our failed fences.
                    log(
                        self.pending.index,
                        "GuC ready; every published engine's defaults, private PPGTT store and retirement verified",
                    );
                }
            }
            (Phase::Huc, GtState::SchedulingReady) => {
                if gt.prepare_huc(now).map_err(RuntimeError::Gt)? {
                    state.phase = Phase::Mert;
                }
            }
            (Phase::Mert, GtState::SchedulingReady) => {
                if gt
                    .prepare_mert(now, || {
                        narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                            == Ok(Some(narf_bus::pci::PciPowerState::D0))
                    })
                    .map_err(RuntimeError::Gt)?
                {
                    if self.pending.smallbar {
                        let authority = state
                            .smallbar_authority
                            .as_ref()
                            .ok_or(RuntimeError::State)?;
                        let grant = match gt.smallbar_grant(authority) {
                            Ok(grant) => {
                                state.smallbar_grant_deadline = None;
                                grant
                            }
                            Err(GtError::Busy) => {
                                let deadline = *state
                                    .smallbar_grant_deadline
                                    .get_or_insert(now.saturating_add(50_000_000));
                                if now < deadline {
                                    return Ok(());
                                }
                                return Err(RuntimeError::Gt(GtError::Busy));
                            }
                            Err(error) => return Err(RuntimeError::Gt(error)),
                        };
                        self.pending
                            .card
                            .publish_smallbar_vram(gt, grant)
                            .map_err(|_| RuntimeError::State)?;
                    }
                    state.phase = Phase::DisplayRecovery;
                }
            }
            (Phase::Running, GtState::SchedulingReady) => {
                if reconfiguration_power {
                    if let Some(control) = &self.ccs_control {
                        let epoch = self.user_epoch.load(Ordering::Acquire);
                        if control
                            .begin(gt, epoch, now, |mode| {
                                self.close_controls();
                                self.close_user_epoch();
                                state.irq.take();
                                state.irq_tried = false;
                                crate::intel_gpu_kms::quarantine_for_gt_reset(&self.pending.bar);
                                state.parked_epoch = None;
                                state.ccs_mode = Ok(mode);
                                state.recovery.fault();
                            })
                            .map_err(RuntimeError::Gt)?
                            .is_some()
                        {
                            state.recovery.adopted_stop(gt).map_err(RuntimeError::Gt)?;
                            state.phase = Phase::Cleaning;
                            return Ok(());
                        }
                    }
                }
                use crate::intel_gpu_guc_sched::SlpcState;
                match gt.slpc() {
                    SlpcState::Running if !state.slpc_reported => {
                        state.slpc_reported = true;
                        log(self.pending.index, "GuC SLPC running; GuC controls RC6");
                    }
                    SlpcState::Unavailable if !state.slpc_reported => {
                        state.slpc_reported = true;
                        log(
                            self.pending.index,
                            "GuC SLPC controls unavailable; retaining current firmware policy",
                        );
                    }
                    _ => {}
                }
                self.service_media(state, now);
            }
            (Phase::Cleaning, GtState::Stopped) => {
                state.phase = if state.recovery.after_stop(gt).map_err(RuntimeError::Gt)? {
                    Phase::Cold
                } else {
                    Phase::Failed
                };
            }
            _ => return Err(RuntimeError::State),
        }
        Ok(())
    }

    async fn run(self: Arc<Self>) {
        // Read-only display format discovery is refreshed after successful GT
        // publication, outside this owner's mutex and without waiting for KMS.
        let mut display_formats_pending = None;
        // The future owns availability. Cancellation closes cached admission,
        // while this card-lifetime Owner continues retaining any DMA graph.
        let Ok(_worker) = self.reset_publication.worker(self.user_epoch.clone()) else {
            return;
        };
        let mut reconfiguration_power = None;
        // intel_hpd_poll_enable while an integrated function is runtime-
        // suspended, and the wakeref of a polled detect, held until the
        // resumed GT is running again (its restart is not synchronous).
        let mut hpd_poll = display_rpm::HpdPoll::default();
        let mut hpd_awake: Option<Awake> = None;
        loop {
            // Policy changes may invoke PCI resume/GT park callbacks, so
            // service the card-lifetime actor before acquiring the GT mutex.
            self.runtime_power
                .service(|| {
                    !self.suspended.load(Ordering::Acquire)
                        && self.user_epoch.load(Ordering::Acquire) != 0
                        && matches!(
                            narf_bus::pci::power_state(&self.pending.cap, &self.pending.device,),
                            Ok(Some(_))
                        )
                })
                .await;
            if !self.suspended.load(Ordering::Acquire) {
                if !self.display_profile() || self.pm.device.status() == RpmStatus::Active {
                    hpd_poll.active();
                    crate::intel_gpu::service_external_sst(&self.pending.bar);
                } else if hpd_awake.is_none() && hpd_poll.due(narf_time::monotonic_ns()) {
                    // A runtime-suspended display touches no register: one
                    // polled detect per DRM_OUTPUT_POLL_PERIOD, under a
                    // wakeref that resumes the function first.
                    if let Ok(awake) = Awake::take(&self).await {
                        crate::intel_gpu::service_external_sst(&self.pending.bar);
                        hpd_awake = Some(awake);
                    }
                }
            }
            let mut reconfiguration_power_failed = false;
            // Runtime resume can acquire this same GT mutex. Never request
            // power while holding it, and retain the usage reference across
            // verified stop, all new probes and epoch publication.
            if self
                .ccs_control
                .as_ref()
                .is_some_and(|control| control.needs_power())
                && !self.suspended.load(Ordering::Acquire)
            {
                if reconfiguration_power.is_none() {
                    match Awake::take(&self).await {
                        Ok(awake) => reconfiguration_power = Some(awake),
                        Err(_) => {
                            reconfiguration_power_failed = true;
                            if let Some(control) = &self.ccs_control {
                                control.close();
                            }
                        }
                    }
                }
            } else {
                drop(reconfiguration_power.take());
            }
            let mut wait = None;
            let mut delay_us = 500;
            let mut settled = false;
            if !self.suspended.load(Ordering::Acquire) {
                let mut state = self.state.lock().await;
                // Snapshot the IRQ epoch before servicing any status. The
                // waiter observes an edge even before its first poll.
                if let Some(irq) = state.irq.as_ref().filter(|_| !reconfiguration_power_failed) {
                    wait = Some(narf_interrupts::wait_for_irq(irq.vector()));
                    match irq.service(narf_time::monotonic_ns()) {
                        Ok(pending) => delay_us = if pending { 10 } else { 10_000 },
                        Err(_) => {
                            drop(wait.take());
                            state.irq.take();
                            log(
                                self.pending.index,
                                "IRQ delivery closed; using timer completion",
                            );
                        }
                    }
                }
                let stepped = if reconfiguration_power_failed {
                    Err(RuntimeError::Authority)
                } else {
                    self.step(&mut state, reconfiguration_power.is_some())
                };
                if let Err(error) = stepped {
                    state.recovery.fault();
                    drop(wait.take());
                    state.irq.take(); // stop delivery before resetting the GT
                    delay_us = 500;
                    let coredump = state.coredump.take();
                    if let Some(gt) = state.gt.as_ref() {
                        use crate::intel_gpu_error::Reason;
                        let reason = match error {
                            RuntimeError::Gt(GtError::WakeLost | GtError::WakeTimeout) => {
                                Reason::WakeLost
                            }
                            RuntimeError::Gt(GtError::Unavailable) => Reason::Unavailable,
                            RuntimeError::Gt(GtError::Scheduling(
                                crate::intel_gpu_guc_sched::SchedulingError::Timeout,
                            )) => Reason::Timeout,
                            RuntimeError::Gt(GtError::Scheduling(
                                crate::intel_gpu_guc_sched::SchedulingError::Protocol,
                            )) => Reason::Protocol,
                            RuntimeError::Gt(
                                GtError::Scheduling(
                                    crate::intel_gpu_guc_sched::SchedulingError::Transport(_),
                                )
                                | GtError::Transport(_),
                            ) => Reason::Transport,
                            RuntimeError::Gt(GtError::Boot(_)) | RuntimeError::Firmware(_) => {
                                Reason::Boot
                            }
                            RuntimeError::Gt(_) => Reason::Recovery,
                            _ => Reason::State,
                        };
                        let window = self.pending.window.clone();
                        let report = gt.error_report(
                            reason,
                            self.user_epoch.load(Ordering::Acquire),
                            narf_time::monotonic_ns(),
                            || {
                                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
                            },
                            |offset| {
                                if narf_bus::pci::power_state(
                                    &self.pending.cap,
                                    &self.pending.device,
                                ) != Ok(Some(narf_bus::pci::PciPowerState::D0))
                                {
                                    return None;
                                }
                                let value = window.read32(offset);
                                (value != u32::MAX).then_some(value)
                            },
                        );
                        if let Some(buffer) = coredump {
                            gt.capture_coredump(
                                buffer,
                                report,
                                narf_time::monotonic_ns(),
                                state
                                    .firmware
                                    .as_ref()
                                    .map_or([0; 32], |firmware| firmware.digest),
                                || {
                                    narf_bus::pci::power_state(
                                        &self.pending.cap,
                                        &self.pending.device,
                                    ) == Ok(Some(narf_bus::pci::PciPowerState::D0))
                                },
                            );
                        }
                        crate::intel_gpu_error::record(self.pending.index, report);
                    }
                    self.close_controls();
                    if let Some(control) = &self.ccs_control {
                        control.close();
                    }
                    self.close_user_epoch();
                    // A display waiter can depend on one of our fences.
                    // Poison its proofs synchronously before reset; never
                    // await the KMS mutex while holding this GT reset mutex.
                    crate::intel_gpu_kms::quarantine_for_gt_reset(&self.pending.bar);
                    state.parked_epoch = None; // a failed resume is a real loss
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "intel-gt card{}: closed after {:?}",
                        self.pending.index,
                        error
                    );
                    state.phase = Phase::Failed;
                    let _ = self.retire_media(&mut state, narf_time::monotonic_ns());
                    // All owner-specific diagnostics/IRQ/admission/display
                    // ordering above precedes the shared hardware cleanup.
                    let State { recovery, gt, .. } = &mut *state;
                    if let Some(gt) = gt {
                        if recovery.begin_cleanup(gt, narf_time::monotonic_ns()) == Ok(true) {
                            state.phase = Phase::Cleaning;
                        }
                    }
                }
                if state.phase == Phase::DisplayRecovery {
                    drop(state);
                    if crate::intel_gpu_kms::recover_after_gt_reset(&self.pending.bar)
                        .await
                        .is_err()
                    {
                        log(
                            self.pending.index,
                            "display recovery failed; retained scanout remains quarantined",
                        );
                    }
                    state = self.state.lock().await;
                    if state.phase == Phase::DisplayRecovery
                        && !self.suspended.load(Ordering::Acquire)
                    {
                        if let Some(epoch) = state.gt.as_ref().and_then(GuCGt::user_epoch) {
                            let configuration =
                                state.gt.as_ref().and_then(GuCGt::compute_configuration);
                            let log_incarnation = state
                                .gt
                                .as_ref()
                                .and_then(GuCGt::log_incarnation)
                                .unwrap_or(0);
                            let ready = {
                                let State { recovery, gt, .. } = &mut *state;
                                gt.as_ref().and_then(|gt| recovery.ready(gt).ok())
                            };
                            let mut reset_published = false;
                            let publish = || {
                                let Some(ready) = ready else {
                                    return;
                                };
                                if ready.publish().is_err() {
                                    return;
                                }
                                reset_published = true;
                                display_formats_pending = Some(epoch);
                                self.power_controls.activate(epoch);
                                self.runtime_power.activate(epoch);
                                if let Some(hwmon) = &self.hwmon {
                                    hwmon.activate(epoch);
                                }
                                self.user_epoch.store(epoch, Ordering::Release);
                                crate::intel_gpu_guc_log::stream::publish(
                                    &self.log_publication,
                                    log_incarnation,
                                );
                                state.parked_epoch = None;
                                // Local memory reopens before Running is
                                // observable: refault waiters see it ended.
                                drop(state.vram_cpu.take());
                                state.phase = Phase::Running;
                                if let Some(clients) = state.lnl_clients.take() {
                                    clients.release();
                                }
                            };
                            let configured = match (&self.ccs_control, configuration) {
                                (Some(control), Some(configuration)) => {
                                    control.publish_with(epoch, configuration, publish)
                                }
                                (Some(_), None) => Err(narf_filesystem::FsError::NoDevice),
                                (None, _) => {
                                    publish();
                                    Ok(())
                                }
                            };
                            if configured.is_err() || !reset_published {
                                // DisplayRecovery is not a polling phase:
                                // the next step returns State and takes the
                                // common fatal/reset path before admission.
                                self.close_controls();
                                self.close_user_epoch();
                                if let Some(control) = &self.ccs_control {
                                    control.close();
                                }
                                drop(state);
                                narf_scheduler::yield_now().await;
                                continue;
                            }
                        }
                    }
                }
                if state.phase == Phase::Running {
                    if let Some(gt) = state.gt.as_mut() {
                        self.power_controls.service(
                            gt,
                            self.user_epoch.load(Ordering::Acquire),
                            narf_time::monotonic_ns(),
                        );
                    }
                }
                if state.phase == Phase::Running {
                    if let Some(hwmon) = &self.hwmon {
                        let mmio = self.pending.window.clone();
                        hwmon.service_mmio(
                            self.user_epoch.load(Ordering::Acquire),
                            narf_time::monotonic_ns(),
                            &mmio,
                            || {
                                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
                            },
                        );
                    }
                }
                if state.phase == Phase::Running && !state.irq_tried {
                    state.irq_tried = true;
                    let engines = state
                        .gt
                        .as_ref()
                        .and_then(GuCGt::engines)
                        .unwrap_or_default();
                    state.irq = crate::intel_gpu_gt_irq::GtIrq::for_device(
                        self.pending.window.clone(),
                        self.pending.cap,
                        self.pending.device,
                        engines,
                    )
                    .ok();
                    if state.irq.is_some() {
                        log(self.pending.index, "MSI completion delivery installed");
                        delay_us = 10; // first drain before opening tile master
                    } else {
                        log(
                            self.pending.index,
                            "MSI unavailable; using timer completion",
                        );
                    }
                }
                settled = matches!(state.phase, Phase::Running | Phase::Failed | Phase::Stopped);
            }
            if let Some(epoch) = display_formats_pending {
                if crate::intel_gpu_kms::refresh_formats_after_publication(&self.pending.bar, epoch)
                {
                    display_formats_pending = None;
                }
            }
            if (settled && display_formats_pending.is_none())
                || self.suspended.load(Ordering::Acquire)
            {
                // The polled detect's resume finished (or cannot), including
                // the post-publication display pass: its put re-arms
                // autosuspend against a running GT.
                drop(hpd_awake.take());
            }
            self.arm_autosuspend().await;
            narf_scheduler::yield_now().await;
            let deadline = narf_time::Deadline::after_us(delay_us);
            if let Some(wait) = wait {
                let _ = narf_time::timeout(deadline, wait).await;
            } else {
                narf_time::SleepUntil::new(deadline.as_instant()).await;
            }
        }
    }
}

impl Owner {
    /// Start or advance the MTL/Arrow standalone media GT (GT1) beside a
    /// running GT0. One attempt per GT0 incarnation; any refusal is logged
    /// once, its wake requests are released and GT0 is never affected.
    /// The media GuC stays in reset and GT1 is not published to userspace.
    fn service_media(&self, state: &mut State, now: u64) {
        let platform =
            GtPlatform::from_pci(self.pending.device.id.vendor, self.pending.device.id.device);
        // Default-off: without narf.intel.media_gt=1 no media owner exists and
        // every GT0 path below (retire, park, suspend, arena) is unchanged.
        if !crate::intel_gpu_gt::media::admitted(platform, narf_boot::args()) {
            return;
        }
        let Some(platform) = platform else {
            return;
        };
        if self.suspended.load(Ordering::Acquire) {
            return;
        }
        if state.media.is_none() {
            if state.media_guc.is_some() {
                // An earlier media GuC is still stopping or retained (for
                // example after a refused park): drive it, and never reset or
                // re-initialize GT1 underneath it.
                self.service_media_guc(state, now);
                return;
            }
            let Some(facts) = *self.user_facts.lock() else {
                return;
            };
            state.media_reported = false;
            state.media = Some(crate::intel_gpu_gt::media::MediaGt::new(
                platform,
                facts.graphics_version,
            ));
        }
        let media = state.media.as_mut().expect("media owner");
        let core::task::Poll::Ready(result) = media.poll(&self.pending.window, now, || {
            narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                == Ok(Some(narf_bus::pci::PciPowerState::D0))
        }) else {
            return;
        };
        if result.is_ok() {
            self.service_media_guc(state, now);
        }
        if core::mem::replace(&mut state.media_reported, true) {
            return;
        }
        use core::fmt::Write as _;
        let _ = match result {
            Ok(facts) => writeln!(
                narf_console::Writer,
                "intel-gt card{}: media GT {}.{:02} step {} initialized (fuse {:#x}, engines {:#x})",
                self.pending.index,
                facts.ip.version / 100,
                facts.ip.version % 100,
                facts.ip.step,
                facts.fuse,
                facts.engines.bits(),
            ),
            Err(error) => writeln!(
                narf_console::Writer,
                "intel-gt card{}: media GT not started ({:?}); GT0 unaffected",
                self.pending.index,
                error
            ),
        };
    }

    /// One media GuC attempt per media GT owner: boot the MTL GuC image on
    /// GT1 and enable its polled CT. Every refusal stays on GT1.
    fn service_media_guc(&self, state: &mut State, now: u64) {
        use crate::intel_gpu_gt::media::{MediaGuc, MediaGucState};
        use core::fmt::Write as _;
        if state.media_guc.is_none() {
            if core::mem::replace(&mut state.media_guc_tried, true) {
                return;
            }
            let Some(facts) = *self.user_facts.lock() else {
                return;
            };
            // narf.intel.huc=1 beside the admitted media GT stages the MTL
            // HuC on this media GuC (xe_huc.c::xe_huc_init: the media GT owns
            // HuC above graphics 12.55). Linux fails the GT's probe when that
            // firmware cannot be used; NARF starts GT1 without HuC instead.
            let platform =
                GtPlatform::from_pci(self.pending.device.id.vendor, self.pending.device.id.device);
            let huc_wanted = crate::intel_gpu_huc::media_opted_in(platform, narf_boot::args());
            if let Some(platform) = platform.filter(|_| huc_wanted && state.huc.is_none()) {
                let opened = narf_firmware::trusted_loader_authority()
                    .ok_or(RuntimeError::Authority)
                    .and_then(|authority| {
                        authority
                            .derive::<Read>()
                            .map_err(|_| RuntimeError::Authority)
                    })
                    .and_then(|authority| {
                        crate::intel_gpu_huc::Firmware::open(platform, &authority)
                            .map_err(RuntimeError::Firmware)
                    });
                match opened {
                    Ok(huc) => state.huc = Some(huc),
                    Err(error) => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "intel-gt card{}: media HuC firmware refused ({:?}); GT1 starts without HuC",
                            self.pending.index,
                            error
                        );
                    }
                }
            }
            let (Some(gt), Some(firmware), Some(media)) = (
                state.gt.as_ref(),
                state.firmware.as_ref(),
                state.media.as_ref(),
            ) else {
                return;
            };
            let config = BootConfig {
                device_id: self.pending.device.id.device,
                revision: facts.revision,
                huc_upload_bytes: 0,
                uncached_mocs: None,
            };
            let huc = state
                .huc
                .as_ref()
                .filter(|_| huc_wanted)
                .map(|huc| (huc, state.media_huc_established));
            let start = |huc| {
                MediaGuc::start(
                    self.pending.window.clone(),
                    gt.shared_allocator(),
                    firmware,
                    huc,
                    config,
                    media,
                    now,
                )
            };
            // A HuC that cannot be staged (WOPCM, allocation) never keeps
            // GT1 down: start once more exactly as without the option.
            let started = match (start(huc), huc) {
                (Err(error), Some(_)) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "intel-gt card{}: media HuC not staged ({:?}); GT1 starts without HuC",
                        self.pending.index,
                        error
                    );
                    start(None)
                }
                (started, _) => started,
            };
            match started {
                Ok(mut guc) => {
                    // narf.intel.gsc=1: Wa_14015076503 brackets the stop's
                    // GRDOM_FULL, so loaded GSC firmware no longer refuses
                    // media scheduling (xe_gt.c::do_gt_reset).
                    if crate::intel_gpu_gt::media::gsc::admitted(platform, narf_boot::args()) {
                        // A fresh owner has no scheduler: this cannot refuse.
                        let _ = guc.honour_gsc_reset_workaround();
                        // xe_gsc_init fetches the firmware once per device;
                        // check_gsc_availability keeps GSCCS0 only with it.
                        let gsc = state.gsc.get_or_insert_with(|| {
                            let image = crate::intel_gpu_gt::media::gsc::owner::fetch_firmware();
                            GscOwner::new(image.as_deref())
                        });
                        if gsc.available() {
                            let _ = guc.schedule_gsccs();
                        } else {
                            crate::intel_gpu_gt::media::gsc::disable_unavailable_interrupts(
                                &self.pending.window,
                            );
                        }
                    }
                    state.media_guc_reported = false;
                    state.media_huc_reported = false;
                    state.media_guc = Some(guc);
                }
                Err(error) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "intel-gt card{}: media GuC not started ({:?}); GT0 unaffected",
                        self.pending.index,
                        error
                    );
                    return;
                }
            }
        }
        let guc = state.media_guc.as_mut().expect("media GuC owner");
        let polled = guc.poll(now, || {
            narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                == Ok(Some(narf_bus::pci::PciPowerState::D0))
        });
        if let Some(running) = guc.huc_outcome() {
            // RUNNING was reached by this owner's own authentication, or by
            // adopting one an earlier media GuC of this owner established.
            state.media_huc_established |= running;
            if !core::mem::replace(&mut state.media_huc_reported, true) {
                log(
                    self.pending.index,
                    if running {
                        "media HuC running, authenticated via the media GuC"
                    } else {
                        "media HuC unavailable; GT1 continues without HuC"
                    },
                );
            }
        }
        if !matches!(polled, core::task::Poll::Ready(Ok(MediaGucState::Running))) {
            // GT1 leaves native Xe and its sources are masked again before
            // it leaves Running.
            *self.user_media.lock() = None;
            if let Some(irq) = state.irq.as_ref() {
                irq.unroute_media();
                irq.unroute_gsc();
            }
            // GT1 left Running (a poll may also be pending while it runs): a
            // PXP job in flight cannot finish, and the next GT1 start
            // resumes PXP (xe_pxp_pm_suspend/resume).
            if guc.state() != MediaGucState::Running {
                if let Some(irq) = state.irq.as_ref() {
                    irq.unroute_kcr();
                }
                state.pxp.lost();
            }
        } else if let Some(publication) = guc.publication() {
            // Every engine executed and retired its private PPGTT job.
            *self.user_media.lock() = Some(crate::intel_gpu_user::MediaGtStatus {
                epoch: publication.epoch,
                engines: publication.engines,
                gmd: publication.gmd,
                reference_clock: publication.reference_clock,
                topology: publication.topology,
            });
        }
        match polled {
            core::task::Poll::Ready(Ok(MediaGucState::Running)) => {
                // Published engines wake this worker through GT0's tiled
                // MSI; without delivery the worker's timer still polls GT1.
                if let (Some(irq), Some(publication)) = (state.irq.as_ref(), guc.publication()) {
                    if !irq.media_routed() && !state.media_irq_failed {
                        if let Err(error) = irq.route_media(publication.engines) {
                            state.media_irq_failed = true;
                            irq.unroute_media();
                            let _ = writeln!(
                                narf_console::Writer,
                                "intel-gt card{}: media IRQ routing refused ({:?}); GT1 polled",
                                self.pending.index,
                                error
                            );
                        }
                    }
                }
                if !core::mem::replace(&mut state.media_guc_reported, true) {
                    log(
                        self.pending.index,
                        "media GT1 published to native Xe; every VCS/VECS retired a private PPGTT job",
                    );
                    if let Some(slpc) = guc.slpc_status() {
                        let _ = writeln!(
                            narf_console::Writer,
                            "intel-gt card{}: media GT1 SLPC running (RPn {} RPe {} RP0 {} MHz, range {}-{} MHz); GuC controls media C6",
                            self.pending.index,
                            slpc.limits.rpn_mhz,
                            slpc.limits.rpe_mhz,
                            slpc.limits.rp0_mhz,
                            slpc.range.min_mhz,
                            slpc.range.max_mhz,
                        );
                    }
                }
                self.service_gsc(state, now);
            }
            core::task::Poll::Ready(Ok(MediaGucState::Stopped)) if guc.reclaimable() => {
                let faulted = guc.error().is_some();
                state.media_guc = None;
                // The verified stop reset GSCCS0: this GuC's GSC objects go.
                if let Some(gsc) = state.gsc.as_mut() {
                    gsc.end_session(&self.pending.window, true);
                }
                // A faulted media GuC gets one media-GT reset and restart per GT0
                // incarnation, as xe_gt.c::gt_reset_worker (do_gt_reset then
                // do_gt_restart). Probe never performs that full GT reset.
                if faulted && !core::mem::replace(&mut state.media_recovered, true) {
                    let graphics = self.user_facts.lock().map(|facts| facts.graphics_version);
                    let platform = GtPlatform::from_pci(
                        self.pending.device.id.vendor,
                        self.pending.device.id.device,
                    );
                    if let (Some(graphics), Some(platform)) = (graphics, platform) {
                        if let Some(mut old) = state.media.take() {
                            old.abandon(&self.pending.window);
                        }
                        state.media = Some(crate::intel_gpu_gt::media::MediaGt::for_recovery(
                            platform, graphics,
                        ));
                        state.media_reported = false;
                        state.media_guc_tried = false;
                    }
                }
            }
            core::task::Poll::Ready(Err(error)) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gt card{}: media GuC stopping after {:?}; GT0 unaffected",
                    self.pending.index,
                    error
                );
            }
            _ => {}
        }
    }

    /// `narf.intel.gsc=1` beside a running GT1 that schedules GSCCS0: route
    /// the GSC sources once, then advance the GSC (session setup,
    /// xe_gsc_load_start, gsc_work) and log each status it reaches.
    fn service_gsc(&self, state: &mut State, now: u64) {
        let State {
            gsc,
            media_guc,
            huc,
            irq,
            gsc_reported,
            gsc_irq_failed,
            ..
        } = state;
        let (Some(gsc), Some(guc)) = (gsc.as_mut(), media_guc.as_mut()) else {
            return;
        };
        if !guc.gsccs_scheduled() {
            return;
        }
        if let Some(irq) = irq.as_ref() {
            if !irq.gsc_routed() && !*gsc_irq_failed {
                if let Err(error) = irq.route_gsc() {
                    *gsc_irq_failed = true;
                    irq.unroute_gsc();
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "intel-gt card{}: GSC IRQ routing refused ({:?}); GSC polled",
                        self.pending.index,
                        error
                    );
                }
            }
        }
        let events = irq.as_ref().map_or(0, |irq| irq.take_gsc_events());
        // xe_huc_init allocates huc->gsc_pkt only for a GSC-headered image.
        let headers = huc.as_ref().is_some_and(|huc| {
            crate::intel_gpu_gt::media::gsc::HucImage::parse(huc.load().object)
                .is_ok_and(|image| image.gsc_headers)
        });
        let port = GscDsm::new(&self.pending);
        let _ = gsc.poll(now, guc, &self.pending.window, &port, headers, events);
        let status = gsc.status();
        if gsc_reported.replace(status) != Some(status) {
            use crate::intel_gpu_gt::media::gsc::load::Status;
            let errno = match status {
                Status::LoadFail(error) | Status::InitFail(error) => error.errno(),
                Status::Error(error) => error.errno(),
                _ => 0,
            };
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "intel-gt card{}: GSC {:?} ({}; compatibility {:?}, HuC via GSC {:?}{})",
                self.pending.index,
                status,
                errno,
                gsc.compatibility(),
                gsc.huc(),
                if gsc.wedged() { ", wedged" } else { "" }
            );
        }
        self.service_pxp(state, now);
    }

    /// `narf.intel.pxp=1` beside a running GT1 with GSCCS0: xe_pxp_init
    /// once, xe_pxp_pm_resume after every later GT1 start, the KCR route,
    /// the readiness the uAPI reads, and the worker's PXP hardware steps.
    /// Without the option nothing here runs.
    fn service_pxp(&self, state: &mut State, now: u64) {
        use crate::intel_gpu_gt::media::{pxp, MediaGucState, MediaWindow, PxpQueue};
        use core::fmt::Write as _;
        let platform =
            GtPlatform::from_pci(self.pending.device.id.vendor, self.pending.device.id.device);
        if !pxp::admitted(platform, narf_boot::args()) {
            return;
        }
        let Some(platform) = platform else {
            return;
        };
        let State {
            gsc,
            media_guc,
            irq,
            pxp: runtime,
            kcr_irq_failed,
            ..
        } = state;
        let (Some(gsc), Some(guc)) = (gsc.as_mut(), media_guc.as_mut()) else {
            return;
        };
        if guc.state() != MediaGucState::Running || !guc.gsccs_scheduled() {
            return;
        }
        let media = MediaWindow::new(&self.pending.window);
        // xe_pxp_init: GSCCS0, loadable GSC firmware and (below media 35)
        // loadable HuC firmware, then a VCS for terminations. The HuC is in
        // error once either authentication failed.
        let view = pxp::Gt1View {
            gsc_loadable: gsc.status().loadable(),
            huc_staged: guc.huc_object().is_some(),
            vcs: guc.pxp_vcs().is_some(),
            gsc_idle: gsc.idle(),
            gsc_error: gsc.status().error(),
            huc_error: gsc.huc() == Some(false) || guc.huc_outcome() == Some(false),
        };
        let index = self.pending.index;
        // xe_irq_enable_hwe's KCR pair, beside the GSC sources, once PXP
        // exists; then the causes latched since the last pass.
        let kcr = || {
            let Some(irq) = irq.as_ref() else {
                return 0;
            };
            if !irq.kcr_routed() && !*kcr_irq_failed {
                if let Err(error) = irq.route_kcr() {
                    *kcr_irq_failed = true;
                    irq.unroute_kcr();
                    let _ = writeln!(
                        narf_console::Writer,
                        "intel-gt card{}: KCR IRQ routing refused ({:?}); PXP terminations cannot complete",
                        index,
                        error
                    );
                }
            }
            irq.take_kcr_events()
        };
        // xe_gsc_create_host_session_id: a random handle (never logged).
        let resources = || {
            pxp::GemClient::new(platform).map(|client| (client, narf_memory::kaslr::random_u64().0))
        };
        let pass = runtime.service(
            view,
            now,
            &mut PxpQueue::new(guc, now),
            &media,
            resources,
            kcr,
        );
        match pass {
            pxp::Pass::Skipped => {
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gt card{}: PXP skipped: unsatisfied deps (GSC {}, HuC {}, VCS {})",
                    index,
                    view.gsc_loadable,
                    view.huc_staged,
                    view.vcs
                );
            }
            pxp::Pass::InitFailed(error) => {
                // out_kcr_disable; Linux then fails the probe.
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gt card{}: PXP initialization failed ({}); PXP disabled",
                    index,
                    error.errno()
                );
            }
            pxp::Pass::Ran {
                initialized: Some(shared),
                ..
            } => {
                // The display checks protected planes' keys against it
                // (xe_pxp_obj_key_check).
                pxp::set_display_pxp(Some(&shared));
                if let Some(mode) = crate::drm_registry::mode_state(index) {
                    mode.lock().intel_pxp_planes = true;
                }
                *self.user_pxp.lock() = Some(shared);
                log(index, "PXP initialized; KCR enabled");
            }
            pxp::Pass::Disabled | pxp::Pass::ResumeDeferred | pxp::Pass::Ran { .. } => {}
        }
    }

    /// xe_pxp_pm_suspend before GT1 stops: the worker's PXP job finishes
    /// (each step is bounded) or, when the stop cannot `wait`, fails as its
    /// job would; then queues are killed and keys invalidated. `false`
    /// while a job still runs.
    fn suspend_pxp(&self, state: &mut State, now: u64, wait: bool) -> bool {
        use crate::intel_gpu_gt::media::{MediaGucState, MediaWindow, PxpQueue};
        let State { pxp, media_guc, .. } = state;
        let media = MediaWindow::new(&self.pending.window);
        // GT1 no longer running: the job can never finish.
        let mut port = media_guc
            .as_mut()
            .filter(|guc| guc.state() == MediaGucState::Running)
            .map(|guc| PxpQueue::new(guc, now));
        pxp.suspend(now, port.as_mut(), &media, wait)
    }

    /// Release the media GT owner's wake requests and advance a verified
    /// media GuC stop before any GT0 stop, park, suspend or fault cleanup.
    fn retire_media(&self, state: &mut State, now: u64) -> MediaRetire {
        // xe_pxp_pm_suspend first: a PXP job in flight finishes before the
        // media GuC stops, or fails when fault cleanup cannot wait.
        let wait = !matches!(state.phase, Phase::Failed | Phase::Cleaning);
        if !self.suspend_pxp(state, now, wait) {
            return MediaRetire::Pending;
        }
        *self.user_media.lock() = None;
        if let Some(irq) = state.irq.as_ref() {
            irq.unroute_media();
            irq.unroute_gsc();
            irq.unroute_kcr();
        }
        state.media_irq_failed = false;
        state.gsc_irq_failed = false;
        state.kcr_irq_failed = false;
        state.media_reported = false;
        state.media_guc_tried = false;
        state.media_recovered = false;
        // xe_uc_stop_prepare -> xe_gsc_stop_prepare: a running GSC load
        // finishes (each step is bounded) before the media GuC stops. Fault
        // cleanup cannot wait: the interrupted load is LOAD_FAIL.
        if let Some(gsc) = state.gsc.as_mut() {
            if !gsc.quiesce(now, state.media_guc.as_mut(), &self.pending.window) {
                if !matches!(state.phase, Phase::Failed | Phase::Cleaning) {
                    return MediaRetire::Pending;
                }
                gsc.interrupt(&self.pending.window);
            }
        }
        let retired = crate::intel_gpu_gt::media::retire(
            &mut state.media,
            &mut state.media_guc,
            &self.pending.window,
            now,
            || {
                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
            },
        );
        if retired == MediaRetire::Done {
            state.media_guc_reported = false;
            if let Some(gsc) = state.gsc.as_mut() {
                gsc.end_session(&self.pending.window, true);
            }
        }
        retired
    }

    /// Await a proven media stop before GT0 leaves D0. False leaves the media
    /// GuC retained; the caller must not power down or rebuild the arena.
    async fn stop_media(&self, state: &mut State) -> bool {
        // xe_pxp_pm_suspend: let a PXP job finish (bounded by its own
        // deadlines) before the media GuC stops.
        while !self.suspend_pxp(state, narf_time::monotonic_ns(), true) {
            narf_scheduler::yield_now().await;
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(1000).as_instant()).await;
        }
        // xe_gsc_stop_prepare: wait for a running GSC load (bounded by its
        // own step deadlines) before the media GuC stops.
        loop {
            let now = narf_time::monotonic_ns();
            let State { gsc, media_guc, .. } = &mut *state;
            let Some(gsc) = gsc.as_mut() else {
                break;
            };
            if gsc.quiesce(now, media_guc.as_mut(), &self.pending.window) {
                break;
            }
            narf_scheduler::yield_now().await;
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(1000).as_instant()).await;
        }
        if self.retire_media(state, narf_time::monotonic_ns()) == MediaRetire::Done {
            return true;
        }
        let Some(guc) = state.media_guc.as_mut() else {
            return true;
        };
        let stopped = guc
            .stop(|| {
                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
            })
            .await;
        if stopped == crate::intel_gpu_gt::media::MediaGucState::Stopped && guc.reclaimable() {
            state.media_guc = None;
            state.media_guc_reported = false;
            if let Some(gsc) = state.gsc.as_mut() {
                gsc.end_session(&self.pending.window, true);
            }
            return true;
        }
        false
    }
}

/// Whether a (non-small-BAR) owner of `platform`, with or without an owned
/// display, ever allows runtime PM ([`display_rpm::profile`]).
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn autosuspend_profile_eligible(platform: Option<GtPlatform>, has_mode: bool) -> bool {
    display_rpm::profile(platform, has_mode, false).is_ok()
}

impl Owner {
    /// Display-less discrete functions and integrated MTL/Arrow or Gen12
    /// functions with an owned display allow runtime PM. An integrated
    /// function stays active while any display wakeref is held, and a lit
    /// panel holds one, as Linux's display wakeref does.
    fn autosuspend_eligible(&self) -> bool {
        self.profile.is_ok()
    }

    /// VRAM a system suspend would lose: every allocation not covered by a
    /// pinned export's suspend backup (`xe_bo_evict_pinned`).
    fn vram_unsaved(&self) -> bool {
        crate::drm_registry::DrmCard::intel_vram(&*self.pending.card)
            .is_some_and(|pool| pool.unsaved_bytes() != 0)
    }

    /// A refused suspend left power on: drop the pinned exports' backups,
    /// whose VRAM still holds the data.
    async fn discard_vram_backups(&self) {
        if let Some(pool) = crate::drm_registry::DrmCard::intel_vram(&*self.pending.card) {
            for object in pool.restore_pending() {
                object.discard_backup().await;
            }
        }
    }

    fn display_profile(&self) -> bool {
        self.profile == Ok(display_rpm::Profile::Display)
    }

    /// Once the first bring-up publishes users: configure autosuspend, allow
    /// runtime PM and drop the probe reference. Never holds the state lock,
    /// because allowing may immediately invoke `park`.
    async fn arm_autosuspend(&self) {
        if self.autosuspend.load(Ordering::Acquire)
            || !self.autosuspend_eligible()
            || self.user_epoch.load(Ordering::Acquire) == 0
        {
            return;
        }
        self.autosuspend.store(true, Ordering::Release);
        let device = &self.pm.device;
        device.set_autosuspend_delay(AUTOSUSPEND_MS).await;
        device.use_autosuspend(true).await;
        device.mark_last_busy();
        device.allow();
        let _ = device.put_autosuspend();
        self.runtime_power.autosuspend_ready();
    }

    /// Runtime suspend: refuse unless the GT is running and provably idle,
    /// no display wakeref is held and no system sleep owns the function.
    /// Local memory stays allocated (D3hot preserves it), but the LMEM BAR does
    /// not decode outside D0, so kernel CPU access closes and every user CPU
    /// mapping of the BAR is revoked first (xe_pm_runtime_suspend's
    /// vram_userfault release); a later CPU access refaults through runtime resume.
    /// Then stop the GT exactly as for reset, keeping the user epoch published
    /// for the resume. Every refusal below leaves the function in D0 with CPU access open.
    async fn park(self: &Arc<Self>) -> Result<(), RpmError> {
        let mut state = self.state.lock().await;
        // xe_display_pm_runtime_suspend{,_late}: the display wakerefs already
        // kept the RPM core from calling here; re-read the holds (lit pipes,
        // DC_off, the deferred DC re-entry, external routes, KMS work).
        let display = if self.display_profile() {
            display_rpm::hold(self.pending.index, &self.pending.bar)
        } else {
            None
        };
        let local = self.pending.card.intel_vram_used();
        if self.suspended.load(Ordering::Acquire)
            || state.phase != Phase::Running
            || !self.autosuspend_eligible()
            || display.is_some()
        {
            return Err(RpmError::Busy);
        }
        let vram_cpu = self.close_vram_cpu().map_err(|()| RpmError::Busy)?;
        // The media GuC shares GT0's GGTT: prove its stop before GT0 parks.
        // A refusal leaves GT0 running; an unproven stop forbids D3.
        if !self.stop_media(&mut state).await {
            return Err(RpmError::Busy);
        }
        let epoch = self.user_epoch.load(Ordering::Acquire);
        let (epoch, engines, compute) = {
            let State { recovery, gt, .. } = &mut *state;
            recovery
                .accept_park(gt.as_ref().ok_or(RpmError::Failed)?, epoch)
                .map_err(|error| {
                    if error == GtError::Busy {
                        RpmError::Busy
                    } else {
                        RpmError::Failed
                    }
                })?
        };
        state.irq.take(); // mask and synchronize while still in D0
        self.close_controls();
        // Runtime park preserves user_epoch but retires this firmware upload.
        // A queued diagnostic open must never migrate to the resumed image.
        self.close_log_publication();
        state.irq_tried = false;
        let gt = state.gt.as_mut().expect("running GT");
        let stopped = gt.begin_stop(narf_time::monotonic_ns()).is_ok()
            && gt
                .wait_with_access(|| {
                    narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                        == Ok(Some(narf_bus::pci::PciPowerState::D0))
                })
                .await
                == Ok(GtState::Stopped);
        if !stopped {
            // Uncertain hardware: close admission; the worker owns recovery.
            self.close_user_epoch();
            state.phase = Phase::Failed;
            return Err(RpmError::Failed);
        }
        // Verified stopped: reclaim its GGTT owners before D3hot.
        state.gt.take();
        state.parked_epoch = Some((epoch, engines, compute));
        state.vram_cpu = vram_cpu;
        state.phase = Phase::Parked;
        if self.display_profile() {
            // The DMC program and DC target stay across D3hot; the first
            // publication after the resume re-verifies the program.
            crate::intel_gpu_dc_states::runtime_suspend_for_bar(&self.pending.bar);
        }
        // xe_pci_runtime_suspend: D3cold only when xe_pm_d3cold_allowed_toggle
        // allowed it; this kernel cannot (see `d3cold`), so the PCI layer
        // stops at D3hot.
        let d3cold = d3cold::allowed(
            d3cold::evaluate(&self.pending.device),
            local.unwrap_or(0),
            d3cold::DEFAULT_VRAM_THRESHOLD_MB,
        );
        log(
            self.pending.index,
            &alloc::format!("runtime suspended (idle) to D3hot; D3cold {d3cold:?}"),
        );
        Ok(())
    }

    /// Close this card's local memory to the CPU for a runtime suspend:
    /// refuse kernel BAR access (refused while one is in flight), then revoke
    /// the BAR window's user mappings (refused while a fork or an unseen
    /// alias is in flight). `None` without a published VRAM pool.
    fn close_vram_cpu(self: &Arc<Self>) -> Result<Option<VramCpuRevocation>, ()> {
        let Some(pool) = crate::drm_registry::DrmCard::intel_vram(&*self.pending.card) else {
            return Ok(None);
        };
        if !pool.close_cpu_access() {
            return Err(());
        }
        let mut closed = VramCpuRevocation {
            pool,
            revocation: None,
        };
        let (start, len) = closed.pool.cpu_window();
        let refault = Arc::new(VramRefault(Arc::downgrade(self)));
        // On refusal `closed` drops here and reopens kernel access.
        closed.revocation = Some(
            crate::intel_gpu_gem::cpu_mapping::revoke_window(start, len, refault)
                .map_err(|_| ())?,
        );
        Ok(Some(closed))
    }

    /// A runtime-PM reference under which this card's LMEM BAR is CPU
    /// accessible: the function is in D0 and any runtime-resume bring-up has
    /// finished, its publication having reopened local memory. A resume that
    /// failed leaves local memory closed: `NoDevice`.
    /// xe_pm_runtime_get for PXP: the function resumes and stays in D0 while
    /// the reference lives (a PXP queue on the list, a readiness query).
    async fn pxp_wakeref(&self) -> Result<Awake, narf_filesystem::FsError> {
        let awake = Awake::take(self).await?;
        drop(self.lock_running().await);
        Ok(awake)
    }

    async fn vram_wakeref(&self) -> Result<Awake, narf_filesystem::FsError> {
        let awake = Awake::take(self).await?;
        let state = self.lock_running().await;
        if state.vram_cpu.is_some() {
            return Err(narf_filesystem::FsError::NoDevice);
        }
        drop(state);
        Ok(awake)
    }

    /// Runtime resume: the PCI layer restored D0 and config space; restart
    /// the verified bring-up, which adopts the parked epoch at publication.
    /// The restart reloads GuC (and HuC where opted in), re-establishes SLPC
    /// and GuC-controlled RC6 and replays the confirmed SLPC policy. For an
    /// integrated display (`xe_display_pm_runtime_resume`): the card worker
    /// resumes its per-iteration hotplug pass once the function is active
    /// (`intel_hpd_init` / `intel_hpd_poll_disable`; there is no display
    /// interrupt to re-arm), the first publication re-verifies the retained
    /// DMC program before DC5/DC6 is trusted again, and the KMS owner
    /// re-proves its retained resource image (IPC included) on its next use.
    async fn unpark(&self) {
        let mut state = self.state.lock().await;
        if state.phase == Phase::Parked {
            state.phase = Phase::Cold;
            state.lnl_flr = None;
            state.lnl_receipt = None;
            state.probe = None;
            state.recovery.cold();
        }
    }

    /// Whether a non-running GT is resuming under a still-valid epoch, so a
    /// caller should wait rather than see a lost device.
    fn resuming(&self, state: &State) -> bool {
        state.parked_epoch.is_some()
            && !matches!(
                state.phase,
                Phase::Failed | Phase::Cleaning | Phase::Stopped
            )
            && !self.suspended.load(Ordering::Acquire)
    }

    /// The state, once any runtime-resume bring-up has finished or failed.
    /// The lock is released between polls so the worker can progress.
    /// One OA step under the running GT owner and current D0/authority,
    /// retried while a previous close, quiesce or job admission is pending.
    async fn oa_locked<T>(
        &self,
        epoch: u64,
        session: &crate::intel_gpu_oa::Session,
        mut step: impl FnMut(
            &mut ProductionGt,
            u64,
            &mut dyn FnMut() -> bool,
        ) -> Result<T, narf_filesystem::FsError>,
    ) -> Result<T, narf_filesystem::FsError> {
        use narf_filesystem::FsError;
        let deadline = narf_time::monotonic_ns().saturating_add(50_000_000);
        loop {
            let mut state = self.lock_running().await;
            if !crate::intel_gpu_oa::capable() {
                session.fail(FsError::PermissionDenied);
                return Err(FsError::PermissionDenied);
            }
            if epoch == 0
                || epoch != self.user_epoch.load(Ordering::Acquire)
                || state.phase != Phase::Running
                || self.suspended.load(Ordering::Acquire)
                || session.device().card != self.pending.index
            {
                return Err(FsError::NoDevice);
            }
            let gt = state.gt.as_mut().ok_or(FsError::NoDevice)?;
            let mut access = || {
                crate::intel_gpu_oa::capable()
                    && narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                        == Ok(Some(narf_bus::pci::PciPowerState::D0))
            };
            let result = step(gt, narf_time::monotonic_ns(), &mut access);
            if result.as_ref().err() != Some(&FsError::WouldBlock) {
                return result;
            }
            drop(state);
            if narf_time::monotonic_ns() >= deadline {
                return Err(FsError::Busy);
            }
            narf_scheduler::yield_now().await;
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
        }
    }

    async fn lock_running(&self) -> narf_lib::mutex::MutexGuard<'_, State> {
        loop {
            let state = self.state.lock().await;
            if !self.resuming(&state) {
                return state;
            }
            drop(state);
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
}

impl narf_power::device_pm::DevicePmOps for Owner {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
        use narf_power::device_pm::DeviceSuspendError as E;
        if !self.pending.allows_system_suspend() {
            return Err(E::Busy);
        }
        let state = self.state.try_lock().ok_or(E::Busy)?;
        // Legacy synchronous suspend has not run the async GT preparation.
        // Refuse before power loss; never bridge a wait inside an executor poll.
        if !self.suspended.load(Ordering::Acquire)
            || state.phase != Phase::Stopped
            || state.saved.is_none()
        {
            return Err(E::Busy);
        }
        Ok(())
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
        // Keep admission closed until the paired asynchronous D0 settle,
        // PCI/display restore and fresh-policy restart can run with IRQs usable.
        Ok(())
    }
}

impl narf_power::system_pm::AsyncSystemPm for Owner {
    fn prepare_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        Box::pin(async move {
            use narf_power::device_pm::DeviceSuspendError as E;
            // A retained Gen12 GOP has no S3 relight owner. Refuse before
            // touching its display or powering down the function.
            if !self.pending.allows_system_suspend() {
                return Err(E::Busy);
            }
            // pci_pm_suspend runtime-resumes a suspended function before the
            // driver's system suspend: an integrated display must be in D0
            // for the quiesce below. Held until resume_from_suspend.
            let awake = if self.display_profile() {
                Some(Awake::take(self).await.map_err(|_| E::Busy)?)
            } else {
                None
            };
            // Evict any idle VRAM allocations (including DG2 Flat-CCS metadata)
            // to system memory before suspend powers down LMEM.
            if self
                .pending
                .card
                .intel_vram_used()
                .is_some_and(|used| used != 0)
            {
                if let (Some(pool), Some(backend)) = (
                    crate::drm_registry::DrmCard::intel_vram(&*self.pending.card),
                    crate::drm_registry::DrmCard::intel_user_backend(&*self.pending.card),
                ) {
                    if let Some(status) = backend.status().filter(|s| s.epoch != 0) {
                        if crate::intel_gpu_xe::evict_vram_for(
                            backend.as_ref(),
                            &pool,
                            false,
                            0,
                            status.epoch,
                            true,
                        )
                        .await
                        .is_err()
                        {
                            return Err(E::Busy);
                        }
                        // xe_bo_evict_all: dma-buf-pinned exports stay in
                        // place, their contents saved to system memory for
                        // the resume's restore (xe_bo_evict_pinned).
                        if crate::intel_gpu_xe::backup_pinned_vram(
                            backend.as_ref(),
                            &pool,
                            status.epoch,
                        )
                        .await
                        .is_err()
                        {
                            self.discard_vram_backups().await;
                            return Err(E::Busy);
                        }
                    }
                }
            }
            // S3 may lose both data and flat CCS. If VRAM neither evicted nor
            // saved remains, refuse suspend cleanly.
            if self.vram_unsaved() {
                self.discard_vram_backups().await;
                return Err(E::Busy);
            }
            // Retire display GEM fetch before closing the backend or taking
            // its reset mutex. KMS holds this same display mutex while a
            // transaction is armed, so suspend cannot overtake its latch.
            if crate::intel_gpu_kms::quiesce_for_legacy(&self.pending.bar)
                .await
                .is_err()
            {
                self.discard_vram_backups().await;
                return Err(E::Busy);
            }
            // Serialize closing admission with the worker's ready-epoch
            // activation. Display quiescence remains outside this lock.
            let mut state = self.state.lock().await;
            if self.vram_unsaved() {
                drop(state);
                self.discard_vram_backups().await;
                // Failed prepare hooks are not resumed by the coordinator.
                let _ = crate::intel_dpcd_bl::resume_for_bar(&self.pending.bar);
                return Err(E::Busy);
            }
            self.close_controls();
            if let Some(control) = &self.ccs_control {
                control.close();
            }
            self.runtime_power.close();
            self.suspended.store(true, Ordering::Release);
            self.close_user_epoch();
            state.irq.take(); // mask/synchronize while the function is in D0
            state.saved = None;
            // System sleep loses context state: no runtime epoch survives it.
            state.parked_epoch = None;
            let result = async {
                // The media GuC shares GT0's GGTT and must be proven stopped
                // before GT0 stops and the function leaves D0.
                if !self.stop_media(&mut state).await {
                    return Err(E::DriverError);
                }
                if let Some(gt) = &mut state.gt {
                    if !matches!(gt.state(), GtState::Staged | GtState::Stopped) {
                        gt.begin_stop(narf_time::monotonic_ns())
                            .map_err(|_| E::DriverError)?;
                        if gt
                            .wait_with_access(|| {
                                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
                            })
                            .await
                            != Ok(GtState::Stopped)
                        {
                            return Err(E::DriverError);
                        }
                    }
                }
                state.saved = Some(
                    narf_bus::pci::save_config(&self.pending.cap, &self.pending.device)
                        .map_err(|_| E::DriverError)?,
                );
                // Reclaim verified stopped/unpublished mappings while this
                // function is still in D0, before platform firmware can alter
                // the GGTT across S3. Resume constructs a fresh GT owner.
                state.gt.take();
                state.phase = Phase::Stopped;
                Ok(())
            }
            .await;
            if result.is_err() {
                // The coordinator does not resume its failing prepare hook.
                // Restart only a provably stopped/unpublished graph; retain
                // uncertain hardware as failed and let the system abort S3.
                state.phase = if state
                    .gt
                    .as_ref()
                    .is_none_or(|gt| matches!(gt.state(), GtState::Staged | GtState::Stopped))
                {
                    Phase::Cold
                } else {
                    Phase::Failed
                };
                self.suspended.store(false, Ordering::Release);
            }
            // The failed prepare hook is not resumed by the coordinator.
            // AUX is panel-global; restore it after releasing the GT mutex.
            drop(state);
            if result.is_err() {
                // The function never lost power: VRAM still holds the data.
                self.discard_vram_backups().await;
                let _ = crate::intel_dpcd_bl::resume_for_bar(&self.pending.bar);
                // Nova's quiesce turned the panel off; the function is still
                // in D0, so the resume relight lights it again in place.
                if let (DisplayOwner::NovaLakeOwned, Some(mode)) =
                    (self.pending.display, self.pending.mode)
                {
                    let _ = crate::intel_gpu::relight_display(&mode);
                }
            } else if let Some(awake) = awake {
                let old = self.system_awake.lock().replace(awake);
                drop(old);
            }
            result
        })
    }

    fn resume_from_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        Box::pin(async move {
            use narf_power::device_pm::DeviceSuspendError as E;
            let mut state = self.state.lock().await;
            if !self.suspended.load(Ordering::Acquire) {
                return Ok(());
            }
            if let Some(saved) = state.saved.as_ref() {
                narf_bus::pci::set_power_state(
                    &self.pending.cap,
                    &self.pending.device,
                    narf_bus::pci::PciPowerState::D0,
                )
                .map_err(|_| E::DriverError)?;
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
                narf_bus::pci::restore_config(&self.pending.cap, &self.pending.device, saved)
                    .map_err(|_| E::DriverError)?;
            }
            if let Some(mode) = self.pending.mode {
                crate::intel_gpu::relight_display(&mode).ok_or(E::DriverError)?;
            }
            state.phase = Phase::Cold;
            state.lnl_flr = None;
            state.lnl_receipt = None;
            state.probe = None;
            state.recovery.cold();
            state.saved = None;
            self.suspended.store(false, Ordering::Release);
            drop(state);
            // xe_bo_restore_late: pinned exports' backups go back in place
            // once the resumed GT runs (their uses restore them first too).
            if let (Some(pool), Some(backend)) = (
                crate::drm_registry::DrmCard::intel_vram(&*self.pending.card),
                crate::drm_registry::DrmCard::intel_user_backend(&*self.pending.card),
            ) {
                if !pool.restore_pending().is_empty() {
                    narf_scheduler::spawn(restore_pinned_after_resume(
                        self.pending.index,
                        backend,
                        pool,
                    ));
                }
            }
            // The system sleep's runtime-PM reference; the display wakerefs
            // (the relit panel) keep holding the function as before.
            let awake = self.system_awake.lock().take();
            drop(awake);
            Ok(())
        })
    }
}

/// How long a resume's restore of pinned exports waits for the GT.
const RESTORE_WAIT_NS: u64 = 60_000_000_000;

/// `xe_bo_restore_late`'s pinned-external pass after a system resume: copy
/// every pinned export's suspend backup back to its VRAM placement once the
/// resumed GT publishes a user epoch. NARF's GT restarts after the resume
/// hook returns, so this waits for it; a use that comes first (an exec, an
/// importer's map) restores the object itself, and anything else stays
/// refused while its restore is pending.
async fn restore_pinned_after_resume(
    card: u32,
    backend: Arc<dyn crate::intel_gpu_user::UserBackend>,
    pool: Arc<crate::intel_gpu_vram::Vram>,
) {
    let deadline = narf_time::monotonic_ns().saturating_add(RESTORE_WAIT_NS);
    loop {
        if let Some(epoch) = backend.status().map(|s| s.epoch).filter(|e| *e != 0) {
            // A failed copy (a reset ended the epoch) retries in the next one.
            if crate::intel_gpu_xe::restore_pinned_vram(backend.as_ref(), &pool, epoch)
                .await
                .is_ok()
            {
                return;
            }
        }
        if pool.restore_pending().is_empty() {
            return;
        }
        if narf_time::monotonic_ns() >= deadline {
            log(
                card,
                "pinned VRAM exports not restored after resume; they stay refused",
            );
            return;
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
    }
}

/// Queue another owned kernel context probe on the actual registered function.
/// The per-card worker owns CT progression; cancelling the returned waiter
/// never removes the context or releases DMA memory.
pub async fn kernel_probe(index: u32) -> Result<Arc<CompletionFence>, RuntimeError> {
    let owner = OWNERS
        .lock()
        .iter()
        .find(|o| o.pending.index == index)
        .cloned()
        .ok_or(RuntimeError::Device)?;
    let mut state = owner.state.lock().await;
    if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
        return Err(RuntimeError::State);
    }
    state
        .gt
        .as_mut()
        .ok_or(RuntimeError::State)?
        .submit_kernel_probe(narf_time::monotonic_ns())
        .map(|(_, completion)| completion)
        .map_err(RuntimeError::Gt)
}

/// Queue the fixed private-address-space store probe on this PCI function.
/// Wait for completion before checking `result.verify()`. Cancelling the
/// waiter or dropping the result retains the scheduler's complete residency.
pub async fn kernel_ppgtt_probe(
    index: u32,
) -> Result<crate::intel_gpu_exec::PpgttProbeSubmission, RuntimeError> {
    let owner = OWNERS
        .lock()
        .iter()
        .find(|o| o.pending.index == index)
        .cloned()
        .ok_or(RuntimeError::Device)?;
    let mut state = owner.state.lock().await;
    if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
        return Err(RuntimeError::State);
    }
    state
        .gt
        .as_mut()
        .ok_or(RuntimeError::State)?
        .submit_ppgtt_probe(narf_time::monotonic_ns())
        .map_err(RuntimeError::Gt)
}

fn seed_discrete_display_card(
    ip: crate::intel_gpu_xe2lpd::DiscreteDisplayIp,
    console: Option<&crate::intel_gpu::ActiveScanout>,
) -> crate::drm::card::Card {
    use crate::drm::card::{
        Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType, NativeOutput,
    };
    let mut kms = Card::new("intel-gpu", "NARF Intel Arc Display", (1, 0, 0));
    kms.native_atomic = true;
    kms.intel_display = true;
    kms.intel_vram_scanout = true;
    let (mode, status) = match console {
        Some(c) => (
            Some(crate::Mode {
                width: c.width,
                height: c.height,
                refresh_hz: 60,
                bpp: 32,
            }),
            ConnectorStatus::Connected,
        ),
        None => (None, ConnectorStatus::Disconnected),
    };
    kms.crtcs.push(Crtc {
        id: 1,
        mode,
        enabled: console.is_some(),
        primary_fb: None,
        x: 0,
        y: 0,
    });
    kms.vrr_enabled.push((1, false));
    kms.encoders.push(Encoder {
        id: 2,
        encoder_type: EncoderType::Tmds,
        possible_crtcs: 0x1,
        possible_clones: 0,
        crtc_id: console.is_some().then_some(1),
    });
    let modes = mode.into_iter().collect();
    kms.connectors.push(Connector {
        id: 3,
        connector_type: ConnectorType::DisplayPort,
        connector_type_id: 1,
        status,
        encoder_id: console.is_some().then_some(2),
        modes,
    });
    kms.native.push(NativeOutput {
        connector: 3,
        edid: None,
        timings: alloc::vec::Vec::new(),
        color_format: None,
        broadcast_rgb: Some(0),
        vrr_capable: None,
        colorspace: Some(0),
        hdr_output_metadata: Some(0),
        max_bpc: Some(8),
    });
    let _ = ip;
    kms
}

/// Arc cards bind to a GT-only device or discrete display (`DG2` / `BMG`).
/// BAR0 and authority remain with the per-function startup service.
/// The Nova Lake-S display-35 route (`narf.intel.nvl_display=1`) once the
/// firmware primary matched the boot framebuffer `fb`: register fixed-mode
/// KMS over it (the CPU copies each flip into it, as for an external-only
/// Gen12 board) and install the display-preserving GT owner beside it. The
/// probe takes this route without `narf.intel.nvl_modeset=1`, or after the
/// owned takeover refused; system suspend stays refused on it.
pub(crate) fn probe_nvl_display(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    fb: narf_graphics_driver::generic::GenericFb,
) -> Result<(), narf_bus::ProbeError> {
    if GtPlatform::from_pci(device.id.vendor, device.id.device) != Some(GtPlatform::NovaLakeS) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if PENDING.lock().iter().any(|p| p.device.addr == device.addr)
        || OWNERS
            .lock()
            .iter()
            .any(|o| o.pending.device.addr == device.addr)
    {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: the PCI probe grants exclusive ownership of this function's BAR0.
    let bar = unsafe { narf_bus::bar::map_bar(&device, 0) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let index = crate::drm_registry::count() as u32;
    let card = Arc::new(IntelGpuCard::new(
        alloc::format!("card{index}"),
        device.id.vendor,
        device.id.device,
        device.id.subsystem_vendor,
        device.id.subsystem_id,
    ));
    let assigned = crate::drm_registry::register_drm_card_with_state(
        card.clone(),
        crate::intel_gpu::firmware_fixed_mode_card(fb),
    );
    if !install_profile(
        assigned,
        card,
        device,
        cap,
        bar,
        None,
        DisplayOwner::NovaLake,
    ) {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-gpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

/// The boot option that installs DG1's KMS owner over its firmware-lit
/// Pipe A, as DG2 and Battlemage get theirs (default off).
pub const DG1_KMS_OPT_IN: &str = "narf.intel.dg1_kms";

/// `narf.intel.dg1_kms=1`, with the strict grammar every Intel opt-in uses
/// ([`crate::intel_gpu_gt::boot_opt_in`]).
pub fn dg1_kms_requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, DG1_KMS_OPT_IN)
}

pub(crate) fn probe_discrete(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    let platform = GtPlatform::from_pci(device.id.vendor, device.id.device)
        .ok_or(narf_bus::ProbeError::NotForThisDriver)?;
    if !platform.is_discrete() && !platform.is_headless_integrated() {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if PENDING.lock().iter().any(|p| p.device.addr == device.addr)
        || OWNERS
            .lock()
            .iter()
            .any(|o| o.pending.device.addr == device.addr)
    {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: the PCI probe grants exclusive ownership of this function's BAR0.
    let bar = unsafe { narf_bus::bar::map_bar(&device, 0) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // LMEM BAR: write-combining for the prefetchable window. A failed or
    // conflicting mapping leaves VRAM unpublished rather than refusing the GT.
    let lmem = if platform.is_discrete() {
        // SAFETY: the same exclusive probe ownership covers BAR2.
        unsafe { narf_bus::bar::map_bar(&device, 2) }.ok()
    } else {
        None
    };
    let index = crate::drm_registry::count() as u32;
    let card = Arc::new(IntelGpuCard::new(
        alloc::format!("card{index}"),
        device.id.vendor,
        device.id.device,
        device.id.subsystem_vendor,
        device.id.subsystem_id,
    ));
    if let Some(lmem) = lmem {
        // SAFETY: this card's own BAR2, owned exclusively by this probe.
        unsafe { card.install_lmem_bar(lmem) };
    }
    let display_window = crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap);
    // DG1's display gets its KMS owner only with `narf.intel.dg1_kms=1`
    // (default off: its lit display keeps the GT-only profile, as before).
    let admitted = platform != GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::Dg1)
        || dg1_kms_requested(narf_boot::args());
    let discrete_display = (platform.has_display() && admitted)
        .then(|| crate::intel_gpu_xe2lpd::DiscreteDisplayIp::identify(&display_window, platform))
        .and_then(Result::ok);
    let discrete_console = discrete_display
        .and_then(|_| crate::intel_gpu_xe2lpd::discrete_pipe_a_scanout(&display_window));
    let assigned = if let Some(ip) = discrete_display {
        let kms = seed_discrete_display_card(ip, discrete_console.as_ref());
        crate::drm_registry::register_drm_card_with_state(card.clone(), kms)
    } else {
        crate::drm_registry::register_drm_card(card.clone())
    };
    let lit = discrete_display_lit(platform, &display_window);
    if install(assigned, card, device, cap, bar, None, None) && lit {
        if let Some(pending) = PENDING
            .lock()
            .iter_mut()
            .find(|p| p.device.addr == device.addr)
        {
            pending.display_lit = true;
        }
    }
    if let (Some(ip), Some(console)) = (discrete_display, discrete_console) {
        crate::intel_gpu_kms::install_discrete(assigned, ip, bar, device, cap, console);
    }
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-gpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_gt_compute_boot_selection_is_unambiguous_and_immutable() -> TestResult {
        use narf_boot::args::KernelCmdline;
        for (raw, expected) in [
            ("", 1),
            ("quiet", 1),
            ("narf.intel.ccs_mode=1", 1),
            ("narf.intel.ccs_mode=2", 2),
            ("narf.intel.ccs_mode=3", 3),
            ("narf.intel.ccs_mode=4", 4),
            ("-- narf.intel.ccs_mode=4", 1),
        ] {
            assert_eq!(ccs_boot_mode(KernelCmdline::new(raw)), Ok(expected));
        }
        for raw in [
            "narf.intel.ccs_mode",
            "narf.intel.ccs_mode=",
            "narf.intel.ccs_mode=0",
            "narf.intel.ccs_mode=5",
            "narf.intel.ccs_mode=-1",
            "narf.intel.ccs_mode=02",
            "narf.intel.ccs_mode=2 narf.intel.ccs_mode=2",
            "narf.intel.ccs_mode=1 narf.intel.ccs_mode=2",
            "narf.intel.ccs_mode=1 narf.intel.ccs_mode",
        ] {
            assert_eq!(
                ccs_boot_mode(KernelCmdline::new(raw)),
                Err(RuntimeError::Configuration)
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_compute_boot_selection_is_unambiguous_and_immutable
    );

    /// The runtime-suspend local-memory guard reopens the pool when it ends,
    /// whether or not a user revocation was taken, and a refault whose owner
    /// is gone fails (SIGBUS) instead of waiting.
    fn smoke_gt_vram_cpu_revocation_reopens_pool_and_orphan_refault_fails() -> TestResult {
        use crate::intel_gpu_vram::{Vram, VramLayout};
        use core::task::{Context, Poll};
        use narf_filesystem::mmap_relocation::{DeviceFrameRefault, DeviceRefaultError};
        let frame = match narf_memory::frame::alloc_pages_on(0, 4) {
            Ok(frame) => frame,
            Err(_) => return TestResult::Skip("64 KiB fixture allocation"),
        };
        let bar = narf_bus::bar::MmioRegion {
            phys: frame.start_address(),
            virt: frame.start_address().kernel_mut_ptr::<u8>() as u64,
            len: 65536,
            kind: narf_bus::bar::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: private fixture RAM stands in for one exclusively owned BAR.
        let pool = unsafe {
            Vram::new(
                bar,
                VramLayout {
                    tile_size: 65536,
                    tile_offset: 0,
                    usable: 65536,
                },
            )
        }
        .unwrap();
        assert!(pool.close_cpu_access());
        let guard = VramCpuRevocation {
            pool: pool.clone(),
            revocation: None,
        };
        assert!(pool.cpu_access().is_none());
        drop(guard);
        assert!(pool.cpu_access().is_some());
        let mut refault = VramRefault(Weak::new()).refault(bar.phys);
        let outcome = refault
            .as_mut()
            .poll(&mut Context::from_waker(core::task::Waker::noop()));
        assert_eq!(outcome, Poll::Ready(Err(DeviceRefaultError::Bus)));
        drop(pool);
        narf_memory::frame::free_pages(frame, 4);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_vram_cpu_revocation_reopens_pool_and_orphan_refault_fails
    );

    fn smoke_gt_private_startup_probes_cover_every_sparse_physical_engine() -> TestResult {
        use crate::intel_gpu_engine::{Engine, EngineSet};
        let engines = EngineSet::of(&[
            Engine::Rcs0,
            Engine::Bcs0,
            Engine::Bcs8,
            Engine::Ccs1,
            Engine::Ccs3,
        ]);
        let mut current = Engine::Rcs0;
        let mut visited = alloc::vec![current];
        while let Some(next) = next_probe_engine(engines, current).unwrap() {
            visited.push(next);
            current = next;
        }
        assert_eq!(
            visited,
            [
                Engine::Rcs0,
                Engine::Bcs0,
                Engine::Bcs8,
                Engine::Ccs1,
                Engine::Ccs3
            ]
        );
        assert_eq!(
            next_probe_engine(engines, Engine::Ccs0),
            Err(RuntimeError::State)
        );
        assert_eq!(
            next_probe_engine(EngineSet::default(), Engine::Rcs0),
            Err(RuntimeError::State)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_private_startup_probes_cover_every_sparse_physical_engine
    );

    fn smoke_gt_pci_identity_and_virtualization_admission() -> TestResult {
        // PCIe extended-capability headers: ID[15:0], version[19:16],
        // next[31:20]. SR-IOV Control.VF Enable is bit0 at capability+8.
        let mut cfg: BTreeMap<u16, u32> = [(0, 0x7d558086), (8, 3)].into_iter().collect();
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Ok(3)
        );
        for unreadable in [8, 0x100] {
            assert_eq!(
                pci_identity(
                    |off| Ok(if off == unreadable {
                        u32::MAX
                    } else {
                        *cfg.get(&off).unwrap_or(&0)
                    }),
                    0x8086,
                    0x7d55
                ),
                Err(RuntimeError::Device)
            );
        }
        cfg.insert(0x100, 0x20010001);
        cfg.insert(0x200, 0x18010010);
        cfg.insert(0x180, 0x0001000f);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Ok(3)
        );
        cfg.insert(0x208, 1);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.insert(0x208, 0);
        cfg.insert(0x210, 1);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.insert(0x210, 0);
        cfg.insert(0x180, 0x2001000f);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.insert(0x180, 0x1811000f);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.insert(0x180, 0x0801000f);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.clear();
        cfg.insert(0, 0x7d558086);
        cfg.insert(8, 3);
        for i in 0..65u16 {
            cfg.insert(0x100 + i * 16, (u32::from(0x110 + i * 16) << 20) | 0x10001);
        }
        let mut count = 0;
        assert_eq!(
            pci_identity(
                |off| {
                    count += 1;
                    Ok(*cfg.get(&off).unwrap_or(&0))
                },
                0x8086,
                0x7d55
            ),
            Err(RuntimeError::Device)
        );
        assert_eq!(count, 66); // identity + revision + at most64 capability reads
        assert_eq!(
            pci_identity(|_| Err(RuntimeError::Authority), 0x8086, 0x7d55),
            Err(RuntimeError::Authority)
        );
        assert_eq!(
            pci_identity(|_| Ok(0xffffffff), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_pci_identity_and_virtualization_admission
    );
    /// A lit discrete display admits the GT while every plane and cursor
    /// fetches below the arena and no DSB runs; a fetch near or in the arena,
    /// a running DSB or an unreadable plane refuses. Planes past the source
    /// inventory are never read; integrated parts take no discrete path.
    fn smoke_gt_discrete_display_admits_fetches_below_the_arena() -> TestResult {
        use core::cell::Cell;
        struct Io {
            values: BTreeMap<u64, u32>,
            missing_high_planes: bool,
            absent: Cell<usize>,
        }
        impl MmioWindow for Io {
            fn read32(&self, r: u64) -> u32 {
                if self.missing_high_planes
                    && (0x70000..0x74000).contains(&r)
                    && [0x680, 0x780].contains(&(r & 0xfff))
                {
                    self.absent.set(self.absent.get() + 1);
                    return u32::MAX;
                }
                *self.values.get(&r).unwrap_or(&0)
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("read-only discrete display admission wrote MMIO")
            }
        }
        let io = |values: &[(u64, u32)], missing_high_planes| Io {
            values: values.iter().copied().collect(),
            missing_high_planes,
            absent: Cell::new(0),
        };
        let dg1 = GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::Dg1);
        for (platform, planes) in [
            (GtPlatform::Alchemist, 5),
            (GtPlatform::Battlemage, 5),
            (dg1, 7),
        ] {
            let high = planes == 5;
            let dark = io(&[], high);
            assert_eq!(validate_discrete_display(platform, &dark), Ok(()));
            assert!(!discrete_display_lit(platform, &dark));
            for pipe in 0..4 {
                for plane in 0..planes {
                    let ctl = 0x70180 + pipe * 0x1000 + plane * 0x100;
                    // GOP scanout at GGTT 0, or anywhere below 192 MiB.
                    for surf in [0, 0x0bff_f000] {
                        let lit = io(&[(ctl, 1 << 31), (ctl + 0x1c, surf)], high);
                        assert_eq!(validate_discrete_display(platform, &lit), Ok(()));
                        assert!(discrete_display_lit(platform, &lit));
                        assert_eq!(lit.absent.get(), 0);
                    }
                    for refused in [
                        io(&[(ctl, 1 << 31), (ctl + 0x1c, 0x0c00_0000)], high),
                        io(&[(ctl, 1 << 31), (ctl + 0x1c, 0x1000_0000)], high),
                        io(&[(ctl, u32::MAX)], high),
                    ] {
                        assert_eq!(
                            validate_discrete_display(platform, &refused),
                            Err(RuntimeError::Device)
                        );
                        assert_eq!(refused.absent.get(), 0);
                    }
                }
                let base = 0x70000 + pipe * 0x1000;
                let cursor = io(&[(base + 0x80, 0x27), (base + 0x84, 0x1000_0000)], high);
                assert_eq!(
                    validate_discrete_display(platform, &cursor),
                    Err(RuntimeError::Device)
                );
                assert!(discrete_display_lit(platform, &cursor));
                let dsb = io(&[(base + 0xc08, 1 << 31)], high);
                assert_eq!(
                    validate_discrete_display(platform, &dsb),
                    Err(RuntimeError::Device)
                );
            }
        }
        struct NoRead;
        impl MmioWindow for NoRead {
            fn read32(&self, _: u64) -> u32 {
                panic!("non-discrete inventory read forbidden display registers")
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("non-discrete inventory wrote display registers")
            }
        }
        assert_eq!(
            validate_discrete_display(GtPlatform::ArcticSoundM, &NoRead),
            Ok(())
        );
        assert!(!discrete_display_lit(GtPlatform::ArcticSoundM, &NoRead));
        for platform in [
            GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake),
            GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake),
        ] {
            assert_eq!(
                validate_discrete_display(platform, &NoRead),
                Err(RuntimeError::Device)
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_discrete_display_admits_fetches_below_the_arena
    );

    /// Nova Lake-S: only the owned display-35 route (an owned console with
    /// its resume relight) admits system suspend; the firmware primary keeps
    /// refusing it. The owned route's display-preserving profile needs Nova
    /// Lake-S and a lit mode.
    fn smoke_gt_nvl_owned_display_admits_system_suspend() -> TestResult {
        assert!(!display_suspend_admitted(DisplayOwner::NovaLake, false));
        assert!(display_suspend_admitted(DisplayOwner::NovaLakeOwned, false));
        assert!(!display_suspend_admitted(DisplayOwner::NovaLakeOwned, true));
        assert!(display_suspend_admitted(DisplayOwner::PantherLake, false));
        assert!(display_suspend_admitted(DisplayOwner::Standard, false));
        let nvl = GtPlatform::NovaLakeS;
        assert_eq!(
            nvl_profile(nvl, true, true),
            Some(LnlProfile::DisplayPreserving)
        );
        assert_eq!(nvl_profile(nvl, true, false), None);
        assert_eq!(nvl_profile(nvl, false, true), Some(LnlProfile::Headless));
        let ptl = GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake);
        assert_eq!(nvl_profile(ptl, true, true), None);
        assert_eq!(nvl_profile(ptl, false, true), Some(LnlProfile::Headless));
        assert_eq!(nvl_profile(GtPlatform::Battlemage, true, true), None);
        // Neither the display-30 nor the display-20 route admits Nova.
        assert_eq!(ptl_profile(nvl, true, true), None);
        assert_eq!(lnl_profile(nvl, true, true), None);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_nvl_owned_display_admits_system_suspend
    );
}
