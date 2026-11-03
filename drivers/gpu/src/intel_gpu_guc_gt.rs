//! One graphics-GT owner for forcewake, GuC bootstrap and CT memory.
//!
//! Reference: ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! MIT xe_force_wake.c and regs/xe_gt_regs.h, plus xe_guc.c reset protocol.
//! This owner is exclusive, not a refcount shared with the legacy Gen12
//! forcewake manager. The PCI owner supplies runtime-PM and serializes all
//! other reset/firmware users. No userspace submission is admitted here.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_gt_hw::{HardwareError, HardwareInit};
use crate::intel_gpu_gt_registers::{RegisterError, RegisterInit};
use crate::intel_gpu_guc::GuCMessage;
use crate::intel_gpu_guc_boot::{BootAllocator, BootConfig, BootError, BootState, GuCBoot};
use crate::intel_gpu_guc_firmware::GuCFirmware;
use crate::intel_gpu_guc_sched::{GuCScheduler, SchedulingError};
use crate::intel_gpu_guc_transport::{Mailbox, TransportError, TransportState, XeLpgTransport};
use crate::intel_gpu_hwconfig::HardwareConfig;
use crate::intel_gpu_nonpriv::EnginePolicy;
use crate::intel_gpu_rcs::GpuBacking;
use crate::intel_gpu_slpc::SlpcState;
use crate::intel_gpu_topology::{GtTopology, TopologyError};
use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::task::Poll;

fn observation_awake(
    io: &impl MmioWindow,
    platform: GtPlatform,
    hardware: Option<&HardwareInit>,
) -> bool {
    // The LNL sampler shares the existing GT owner and its held media proof.
    // Recheck that proof before every MCR read/write and DMA copy. The window
    // separately invokes current PF/PCI/BAR/D0 authority for each raw access,
    // including the mandatory four root dummy writes before every MMIO read.
    if platform.is_lnl() && !hardware.is_some_and(|hw| hw.ready() && hw.awake(io).is_ok()) {
        return false;
    }
    [0xa188, 0xdfc, 0xa278, 0xd84].into_iter().all(|reg| {
        let value = io.read32(reg);
        value != u32::MAX && value & 1 != 0
    })
}
const REQUEST: u64 = 0xa188;
const WAKE_NS: u64 = 50_000_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GtState {
    Staged,
    Waking,
    PreparingHardware,
    Booting,
    Ready,
    SizingHwconfig,
    CopyingHwconfig,
    EnablingCt,
    CtReady,
    PreparingScheduling,
    StartingScheduling,
    SchedulingReady,
    Recovering,
    RecoveringRender,
    Stopping,
    ResettingEngines,
    ReleasingRender,
    Releasing,
    Stopped,
    Lost,
    /// Execution DMA is retired; host-L2/wake handoff still needs proof.
    StoppingMert,
    /// GuC stopped; drain all present Gen12 command streamers before reset.
    StoppingGen12Cs,
    /// Full reset/DMA idle proven; retain graph until media wake ACK release.
    ReleasingGen12Media,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GtError {
    State,
    Busy,
    Unavailable,
    WakeLost,
    WakeTimeout,
    Boot(BootError),
    Transport(TransportError),
    Poisoned,
    Hardware(HardwareError),
    Registers(RegisterError),
    Scheduling(SchedulingError),
    Topology(TopologyError),
}

struct Parts<M: MmioWindow, A: BootAllocator> {
    boot: GuCBoot<M, A>,
    ct: Option<XeLpgTransport<M, A>>,
    discovery_mailbox: Option<Mailbox<M>>,
    scheduler: Option<GuCScheduler<A>>,
    topology: Option<Arc<GtTopology>>,
    eu_stall: Option<crate::intel_gpu_eu_stall::Collector<A>>,
    mert: Option<crate::intel_gpu_slpc::mert::Mert>,
}

/// The sole owner of the GT kernel-request bit and graphics-GuC mailbox.
/// Drop only reclaims an unpublished or fully stopped owner. Every uncertain
/// state retains the allocator, firmware, CT and MMIO windows together.
pub struct GuCGt<M: MmioWindow, A: BootAllocator> {
    parts: ManuallyDrop<Parts<M, A>>,
    state: GtState,
    deadline: u64,
    requested: bool,
    released: bool,
    hardware: Option<HardwareInit>,
    registers: Option<RegisterInit>,
    engine_policy: Option<EnginePolicy>,
    compute_configuration: Option<(u8, u8)>,
    /// Battlemage tile-0 local memory, probed under register steering. A
    /// malformed layout leaves VRAM unpublished, never guessed.
    vram: Option<crate::intel_gpu_vram::VramLayout>,
    log_stream: Option<crate::intel_gpu_guc_log::stream::Actor>,
    log_fence: u16,
    mert_required: bool,
    smallbar_grant: Option<Arc<crate::intel_gpu_gt::smallbar::DpaGrant>>,
    smallbar_busy_deadline: Option<u64>,
    gen12_reset: Option<crate::intel_gpu_gt::gen12::reset::Reset>,
    /// Standalone media GT: VDBOX/VEBOX forcewake domains (media_gt domain
    /// bits) whose kernel wake the enclosing media owner holds while engines
    /// are programmed and scheduled. Every wake proof also checks them.
    media_wells: u16,
}

impl<M: MmioWindow, A: BootAllocator> core::fmt::Debug for GuCGt<M, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuCGt")
            .field("state", &self.state)
            .field("boot", &self.parts.boot)
            .finish_non_exhaustive()
    }
}

impl<M: MmioWindow, A: BootAllocator> GuCGt<M, A> {
    pub fn stage(
        mmio: M,
        allocator: A,
        firmware: &GuCFirmware,
        config: BootConfig,
    ) -> Result<Self, GtError> {
        GuCBoot::stage(mmio, allocator, firmware, config)
            .map(Self::from_staged)
            .map_err(GtError::Boot)
    }

    /// Physical-function startup. In addition to `stage`'s contract, this
    /// owner exclusively controls render forcewake and MCR steering. PCI power
    /// and the allocator remain owned through verified full GT shutdown.
    pub fn stage_hardware(
        mmio: M,
        allocator: A,
        firmware: &GuCFirmware,
        config: BootConfig,
    ) -> Result<Self, GtError> {
        if firmware.platform().is_headless_integrated() && !allocator.lnl_takeover_ready() {
            return Err(GtError::Boot(BootError::State));
        }
        if firmware.platform().is_xe2() && config.uncached_mocs != Some(3) {
            return Err(GtError::Boot(BootError::Device));
        }
        Self::from_staged_hardware(
            GuCBoot::stage(mmio, allocator, firmware, config).map_err(GtError::Boot)?,
        )
    }

    pub(crate) fn stage_hardware_with_huc(
        mmio: M,
        allocator: A,
        firmware: &GuCFirmware,
        huc: &crate::intel_gpu_huc::Firmware,
        config: BootConfig,
    ) -> Result<Self, GtError> {
        Self::from_staged_hardware(
            GuCBoot::stage_with_huc(mmio, allocator, firmware, huc, config)
                .map_err(GtError::Boot)?,
        )
    }

    /// Finish HuC through the existing single scheduler/CT owner before public
    /// epoch admission. Optional PC failure never pretends HuC is available.
    pub(crate) fn prepare_huc(&mut self, now: u64) -> Result<bool, GtError> {
        let Some(image) = self.parts.boot.huc_upload() else {
            return Ok(true);
        };
        self.admit_scheduling()?;
        let scheduler = self.parts.scheduler.as_mut().ok_or(GtError::State)?;
        if scheduler.huc.started() {
            return Ok(scheduler.huc.done());
        }
        if !scheduler.engines().iter().any(|engine| engine.is_decode()) {
            scheduler.huc.invalidate();
            return Ok(true);
        }
        match scheduler.slpc() {
            SlpcState::Running => {
                scheduler.huc.begin(image, now);
                Ok(false)
            }
            SlpcState::Off | SlpcState::Unavailable => {
                scheduler.huc.invalidate();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(crate) fn huc_version(
        &self,
        epoch: u64,
        mut current: impl FnMut() -> bool,
    ) -> Option<(u8, u8, u8)> {
        if self.parts.boot.platform() != crate::intel_gpu_huc::PLATFORM
            || self.state != GtState::SchedulingReady
            || epoch == 0
            || self.user_epoch() != Some(epoch)
            || !current()
            || self.awake().is_err()
        {
            return None;
        }
        self.parts
            .scheduler
            .as_ref()?
            .huc
            .version(self.parts.boot.window())
    }

    pub(crate) fn from_staged_hardware(boot: GuCBoot<M, A>) -> Result<Self, GtError> {
        let hardware = HardwareInit::new(boot.platform()).map_err(GtError::Hardware)?;
        let mut gt = Self::from_staged(boot);
        gt.hardware = Some(hardware);
        Ok(gt)
    }

    pub(crate) fn from_staged(boot: GuCBoot<M, A>) -> Self {
        assert_eq!(boot.state(), BootState::Staged);
        Self {
            parts: ManuallyDrop::new(Parts {
                boot,
                ct: None,
                discovery_mailbox: None,
                scheduler: None,
                topology: None,
                eu_stall: None,
                mert: None,
            }),
            state: GtState::Staged,
            deadline: 0,
            requested: false,
            released: false,
            hardware: None,
            registers: None,
            engine_policy: None,
            compute_configuration: None,
            vram: None,
            log_stream: None,
            log_fence: crate::intel_gpu_guc_log::stream::FIRST_FENCE,
            mert_required: false,
            smallbar_grant: None,
            smallbar_busy_deadline: None,
            gen12_reset: None,
            media_wells: 0,
        }
    }

    pub fn state(&self) -> GtState {
        self.state
    }

    pub(crate) fn snapshot_guc_log(
        &self,
        buffer: crate::intel_gpu_guc_log::CaptureBuffer,
        epoch: u64,
        now_ns: u64,
        firmware_digest: [u8; 32],
        mut current_access_ok: impl FnMut() -> bool,
    ) -> Result<crate::intel_gpu_guc_log::Snapshot, narf_filesystem::FsError> {
        if self.state != GtState::SchedulingReady || epoch == 0 || self.user_epoch() != Some(epoch)
        {
            return Err(narf_filesystem::FsError::NoDevice);
        }
        let log = self
            .parts
            .boot
            .live_log()
            .ok_or(narf_filesystem::FsError::NoDevice)?;
        buffer.capture(
            log.backing,
            crate::intel_gpu_guc_log::Identity {
                epoch,
                incarnation: log.incarnation,
                now_ns,
                platform: self.parts.boot.platform(),
                firmware_version: log.firmware_version,
                firmware_digest,
            },
            || current_access_ok() && self.awake().is_ok(),
        )
    }

    /// Allocation-free scalar/status capture under this owner's reset lock.
    /// The access predicate checks current D0/PCI authority before even the
    /// wake-proof MMIO reads. Each status read requires current GT/render wake. Failure to
    /// establish that proof preserves the software facts without MMIO data.
    pub(crate) fn error_report(
        &self,
        reason: crate::intel_gpu_error::Reason,
        epoch: u64,
        now_ns: u64,
        mut current_access_ok: impl FnMut() -> bool,
        mut read: impl FnMut(u64) -> Option<u32>,
    ) -> crate::intel_gpu_error::Report {
        crate::intel_gpu_error::Report::capture(
            crate::intel_gpu_error::Capture {
                platform: self.parts.boot.platform(),
                reason,
                epoch,
                now_ns,
                state: self.state,
                engines: self.engines().unwrap_or_default(),
            },
            self.parts.scheduler.as_ref().map_or_else(
                || crate::intel_gpu_error::Contexts::new(0),
                GuCScheduler::diagnostic_contexts,
            ),
            |offset| {
                if !current_access_ok() || self.awake().is_err() {
                    None
                } else {
                    read(offset)
                }
            },
        )
    }

    pub(crate) fn take_error_report(&mut self) -> Option<crate::intel_gpu_error::Report> {
        self.parts
            .scheduler
            .as_mut()
            .and_then(GuCScheduler::take_error_report)
    }

    /// The runtime reset owner calls this after failure detection and before
    /// full teardown, while all log/CT backing remains retained. Firmware may
    /// already have reset an engine: the bundle promises no atomic freeze.
    pub(crate) fn capture_coredump(
        &self,
        buffer: crate::intel_gpu_error::coredump::Armed,
        report: crate::intel_gpu_error::Report,
        now_ns: u64,
        firmware_digest: [u8; 32],
        mut access: impl FnMut() -> bool,
    ) {
        // Linux samples NO_ERROR_CAPTURE at error capture. Our bundle shares
        // global log/CT and other jobs, so skip it completely before any raw
        // source read when a retained compatibility policy is protected.
        if self
            .parts
            .scheduler
            .as_ref()
            .is_some_and(|scheduler| scheduler.diagnostic_protected())
        {
            return;
        }
        let log = self.parts.boot.live_log();
        let identity = log.as_ref().map(|log| crate::intel_gpu_guc_log::Identity {
            epoch: self.user_epoch().unwrap_or(0),
            incarnation: log.incarnation,
            now_ns,
            platform: self.parts.boot.platform(),
            firmware_version: log.firmware_version,
            firmware_digest,
        });
        buffer.capture_with_vm(
            report,
            identity,
            log.as_ref().map(|log| log.backing),
            self.parts
                .ct
                .as_ref()
                .and_then(XeLpgTransport::diagnostic_backing),
            |destination, access| {
                self.parts.scheduler.as_ref().map(|scheduler| {
                    scheduler.diagnostic_backings(
                        access,
                        |info, parent, lane, image, ring, scratch, access| {
                            destination.push(info, parent, lane, image, ring, scratch, access);
                        },
                    )
                })
            },
            |destination, access| {
                self.parts.scheduler.as_ref().map(|scheduler| {
                    scheduler.diagnostic_vms(access, |id, stamp, batch, access| {
                        destination.push(id, stamp, batch, access);
                    })
                })
            },
            || access() && self.awake().is_ok(),
        );
    }

    /// Last validated firmware table. It describes hardware capabilities, not
    /// active engine/fuse masks or permission to admit userspace submissions.
    pub fn hwconfig(&self) -> Option<&HardwareConfig> {
        self.parts.boot.hwconfig()
    }

    /// Engines this GT schedules, once scheduling has been prepared.
    pub fn engines(&self) -> Option<crate::intel_gpu_engine::EngineSet> {
        self.parts.scheduler.as_ref().map(|s| s.engines())
    }

    pub fn vram_layout(&self) -> Option<crate::intel_gpu_vram::VramLayout> {
        self.vram
    }

    pub(crate) fn smallbar_grant(
        &mut self,
        authority: &Arc<crate::intel_gpu_gt::smallbar::Authority>,
    ) -> Result<Arc<crate::intel_gpu_gt::smallbar::DpaGrant>, GtError> {
        let epoch = self.user_epoch().ok_or(GtError::State)?;
        self.vram_access(epoch)?;
        self.admit_scheduling()?;
        let grant = authority
            .derive(self.parts.boot.window(), self.vram.ok_or(GtError::State)?)
            .map_err(Self::smallbar_access_error)?;
        self.smallbar_grant = Some(grant.clone());
        Ok(grant)
    }

    pub(crate) fn vram_needs_ccs_clear(&self) -> bool {
        self.parts.boot.platform() == GtPlatform::Alchemist
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn vram_cpu_access(&self, epoch: u64) -> bool {
        self.vram_access(epoch).is_ok()
    }
    fn smallbar_access_error(error: crate::intel_gpu_gt::lnl::Error) -> GtError {
        if error == crate::intel_gpu_gt::lnl::Error::Busy {
            GtError::Busy
        } else {
            GtError::Unavailable
        }
    }
    fn current_region(&self) -> Result<(), GtError> {
        if let Some(grant) = &self.smallbar_grant {
            grant
                .current(self.parts.boot.window())
                .map_err(Self::smallbar_access_error)?;
        }
        Ok(())
    }
    pub(crate) fn vram_access(&self, epoch: u64) -> Result<(), GtError> {
        if self.state != GtState::SchedulingReady
            || (self.mert_required
                && !self
                    .parts
                    .mert
                    .as_ref()
                    .is_some_and(|owner| owner.sanitizing()))
            || self.parts.boot.platform() != GtPlatform::Battlemage
            || epoch == 0
            || self.user_epoch() != Some(epoch)
        {
            return Err(GtError::State);
        }
        self.awake()?;
        self.current_region()
    }

    /// Cached qualification identity for the physical recovery coordinator.
    /// A software-only/bare GuCGt cannot qualify a physical reset service.
    pub(crate) fn recovery_identity(
        &self,
    ) -> Option<(GtPlatform, crate::intel_gpu_engine::EngineSet, u64)> {
        let platform = self.parts.boot.platform();
        if platform.guc().is_none()
            || !self.hardware.as_ref().is_some_and(HardwareInit::ready)
            || !self.context_defaults_ready()
            || self.user_epoch().is_none_or(|epoch| epoch == 0)
            || self.submission_version().0 != 1
        {
            return None;
        }
        let engines = self
            .engines()
            .filter(|engines| engines.iter().next().is_some())?;
        let incarnation = self
            .log_incarnation()
            .filter(|incarnation| *incarnation != 0)?;
        Some((platform, engines, incarnation))
    }

    /// Cached identity of this exact live firmware log upload; no MMIO.
    pub(crate) fn log_incarnation(&self) -> Option<u64> {
        if self.state != GtState::SchedulingReady {
            return None;
        }
        self.parts.boot.live_log().map(|log| log.incarnation)
    }

    pub(crate) fn attach_log_stream(
        &mut self,
        session: Arc<crate::intel_gpu_guc_log::StreamSession>,
        epoch: u64,
        now: u64,
        digest: [u8; 32],
    ) -> Result<(), narf_filesystem::FsError> {
        use narf_filesystem::FsError;
        let session = session.source_owner();
        if !session.source_open() {
            return Err(FsError::NoDevice);
        }
        if self.state != GtState::SchedulingReady || epoch == 0 || self.user_epoch() != Some(epoch)
        {
            return Err(FsError::NoDevice);
        }
        if let Some(actor) = &self.log_stream {
            return if actor.is(&session) {
                Ok(())
            } else {
                Err(FsError::Busy)
            };
        }
        self.awake().map_err(|_| FsError::NoDevice)?;
        let log = self.parts.boot.live_log().ok_or(FsError::NoDevice)?;
        if !session.matches_incarnation(log.incarnation) {
            return Err(FsError::NoDevice);
        }
        if !log.backing.coherent_for_device() {
            return Err(FsError::Unsupported);
        }
        if self
            .log_fence
            .checked_add(2)
            .is_none_or(|last| last > crate::intel_gpu_guc_log::stream::LAST_FENCE)
        {
            return Err(FsError::Busy);
        }
        let identity = crate::intel_gpu_guc_log::Identity {
            epoch,
            incarnation: log.incarnation,
            now_ns: now,
            platform: self.parts.boot.platform(),
            firmware_version: log.firmware_version,
            firmware_digest: digest,
        };
        if !crate::intel_gpu_guc_log::stream::supported(
            identity.platform,
            identity.firmware_version,
        ) {
            return Err(FsError::Unsupported);
        }
        self.log_stream = Some(crate::intel_gpu_guc_log::stream::Actor::new(
            session,
            identity,
            self.log_fence,
        ));
        self.log_fence += 3;
        Ok(())
    }

    pub(crate) fn poll_log_stream(
        &mut self,
        now: u64,
        mut access: impl FnMut() -> bool,
    ) -> Result<(), GtError> {
        let Some(mut actor) = self.log_stream.take() else {
            return Ok(());
        };
        if self.state != GtState::SchedulingReady || !access() || self.awake().is_err() {
            actor.lost();
            self.log_stream = Some(actor);
            return Ok(());
        }
        let parts = &mut *self.parts;
        let window = parts.boot.window();
        let ack = parts
            .boot
            .platform()
            .guc_forcewake_ack()
            .ok_or(GtError::State)?;
        let log = parts.boot.live_log().ok_or(GtError::State)?;
        let hardware = self.hardware.as_ref().filter(|hw| hw.ready());
        let live = || {
            if !access() {
                return false;
            }
            let request = window.read32(REQUEST);
            let ack = window.read32(ack);
            request != u32::MAX
                && ack != u32::MAX
                && request & 1 != 0
                && ack & 1 != 0
                && hardware.is_none_or(|hw| hw.awake(window).is_ok())
        };
        match actor.poll(
            parts.ct.as_mut().ok_or(GtError::State)?,
            log.backing,
            now,
            live,
        ) {
            Ok(true) => self.log_stream = Some(actor),
            Ok(false) => {}
            Err(error) => {
                self.log_stream = Some(actor);
                self.state = GtState::Lost;
                return Err(GtError::Transport(error));
            }
        }
        Ok(())
    }

    /// Preallocate before scheduling starts. Subsequent startup contexts issue
    /// acknowledged heavy GGTT invalidations before the runtime publishes an
    /// epoch; sampling never adds or rebinds live GGTT mappings afterward.
    pub(crate) fn prepare_eu_stall(&mut self, card: u32) -> Result<(), narf_filesystem::FsError>
    where
        A: Clone,
    {
        use narf_filesystem::FsError;
        if self.state != GtState::Ready
            || self.parts.scheduler.is_some()
            || self.parts.eu_stall.is_some()
        {
            return Err(FsError::Unsupported);
        }
        self.awake().map_err(|_| FsError::NoDevice)?;
        if self.parts.boot.platform().is_lnl()
            && (!observation_awake(
                self.parts.boot.window(),
                self.parts.boot.platform(),
                self.hardware.as_ref(),
            ) || crate::intel_gpu_gt::GraphicsIp::read(
                self.parts.boot.window(),
                self.parts.boot.platform(),
            )
            .is_err())
        {
            return Err(FsError::NoDevice);
        }
        let info = crate::intel_gpu_eu_stall::Info::from_tables(
            card,
            self.parts.boot.platform(),
            self.topology().ok_or(FsError::NoDevice)?,
            self.hwconfig().ok_or(FsError::NoDevice)?,
        )
        .ok_or(FsError::Unsupported)?;
        let collector = crate::intel_gpu_eu_stall::Collector::new(
            self.parts.boot.diagnostic_allocator(),
            info,
        )?;
        self.parts.eu_stall = Some(collector);
        Ok(())
    }
    pub(crate) fn eu_stall_info(&self) -> Option<crate::intel_gpu_eu_stall::Info> {
        self.parts.eu_stall.as_ref().map(|c| c.info())
    }
    pub(crate) fn control_eu_stall(
        &mut self,
        session: Arc<crate::intel_gpu_eu_stall::Session>,
        operation: crate::intel_gpu_eu_stall::Operation,
        mut access: impl FnMut() -> bool,
    ) -> Result<(), narf_filesystem::FsError> {
        use crate::intel_gpu_eu_stall::Operation;
        if !access() {
            if let Some(collector) = self.parts.eu_stall.as_mut() {
                collector.lost();
            }
            return Err(narf_filesystem::FsError::NoDevice);
        }
        self.admit_scheduling()
            .map_err(|_| narf_filesystem::FsError::NoDevice)?;
        let hardware = self.hardware.as_ref();
        let parts = &mut *self.parts;
        let platform = parts.boot.platform();
        let collector = parts
            .eu_stall
            .as_mut()
            .ok_or(narf_filesystem::FsError::NoDevice)?;
        if operation == Operation::Attach {
            return collector.attach(session);
        }
        let window = parts.boot.window();
        collector.control(window, &session, operation == Operation::Enable, || {
            access() && observation_awake(window, platform, hardware)
        })
    }
    pub(crate) fn poll_eu_stall(&mut self, now: u64, mut access: impl FnMut() -> bool) {
        if self.parts.eu_stall.is_none() {
            return;
        }
        if !access() || self.awake().is_err() {
            if let Some(c) = self.parts.eu_stall.as_mut() {
                c.lost();
            }
            return;
        }
        let hardware = self.hardware.as_ref();
        let parts = &mut *self.parts;
        let platform = parts.boot.platform();
        if let Some(collector) = parts.eu_stall.as_mut() {
            let window = parts.boot.window();
            let _ = collector.poll(window, now, || {
                access() && observation_awake(window, platform, hardware)
            });
        }
    }

    /// Caller has checked this unpublished allocation against this card's
    /// retained VRAM pool. Only the trusted CCS-clear factory is executable.
    pub(crate) fn clear_vram(
        &mut self,
        now: u64,
        object: Arc<crate::intel_gpu_gem::GemObject>,
        epoch: u64,
    ) -> Result<Arc<crate::intel_gpu_fence::CompletionFence>, GtError> {
        let gpu_only = object.is_gpu_only();
        if gpu_only {
            self.vram_access(epoch)?;
            object
                .gpu_only_access(self.parts.boot.window())
                .map_err(Self::smallbar_access_error)?;
        }
        if epoch == 0
            || self.user_epoch() != Some(epoch)
            || if gpu_only {
                self.parts.boot.platform() != GtPlatform::Battlemage
                    || self.user_epoch() != Some(epoch)
            } else {
                self.parts.boot.platform() != GtPlatform::Alchemist
            }
        {
            return Err(GtError::State);
        }
        self.admit_scheduling()?;
        let batch = if gpu_only {
            crate::intel_gpu_exec::prepare_smallbar_clear(object)
        } else {
            crate::intel_gpu_exec::prepare_vram_clear(object)
        }
        .map_err(|error| GtError::Scheduling(SchedulingError::Residency(error)))?;
        // SAFETY: factory retains all private mappings and zero source, emits
        // only source-qualified BCS0 CCS clear/flush, and excludes user writes.
        let (_, fence) = unsafe {
            self.parts
                .scheduler
                .as_mut()
                .ok_or(GtError::State)?
                .submit_resident_on(now, crate::intel_gpu_engine::Engine::Bcs0, batch)
                .map_err(GtError::Scheduling)?
        };
        Ok(fence)
    }

    /// Copy only the retained owned ranges on this device; a raw address or
    /// foreign local-memory pool cannot select a DMA source/destination.
    pub(crate) fn copy_objects(
        &mut self,
        now: u64,
        request: crate::intel_gpu_exec::copy::CopyRequest,
        epoch: u64,
        pool: Option<&Arc<crate::intel_gpu_vram::Vram>>,
    ) -> Result<Arc<crate::intel_gpu_fence::CompletionFence>, GtError> {
        if epoch == 0 || self.user_epoch() != Some(epoch) {
            return Err(GtError::State);
        }
        request
            .validate_pool(pool)
            .map_err(|error| GtError::Scheduling(SchedulingError::Residency(error)))?;
        if request.uses_vram() && pool.is_none_or(|pool| self.vram_layout() != Some(pool.layout)) {
            return Err(GtError::Unavailable);
        }
        if request.uses_gpu_only() {
            self.vram_access(epoch)?;
            pool.ok_or(GtError::Unavailable)?
                .smallbar_access(self.parts.boot.window())
                .map_err(Self::smallbar_access_error)?;
        }
        self.admit_scheduling()?;
        let batch = request
            .prepare(self.parts.boot.platform())
            .map_err(|error| GtError::Scheduling(SchedulingError::Residency(error)))?;
        // SAFETY: the private factory emits only bounded copies among its
        // immutable PPGTT mappings, auxiliary copy/flush and BB_END. Implicit
        // reservations exclude conflicting kernel/dma-buf copies until the
        // complete resident graph retires; no user batch controls commands.
        let (_, fence) = unsafe {
            self.parts
                .scheduler
                .as_mut()
                .ok_or(GtError::State)?
                .submit_resident_on(now, crate::intel_gpu_engine::Engine::Bcs0, batch)
                .map_err(GtError::Scheduling)?
        };
        Ok(fence)
    }

    pub fn topology(&self) -> Option<&GtTopology> {
        self.parts.topology.as_deref()
    }

    /// Sample the timestamp clock with current wake and stable GMD identity.
    /// MIT xe_gt_clock.c: crystal selector[5:3], timestamp divisor[2:1].
    pub fn device_facts(&mut self) -> Result<crate::intel_gpu_user::DeviceFacts, GtError> {
        if self.user_epoch().is_none() {
            return Err(GtError::State);
        }
        self.awake()?;
        let window = self.parts.boot.window();
        let ip = crate::intel_gpu_gt::GraphicsIp::read(window, self.parts.boot.platform())
            .map_err(|_| GtError::Unavailable)?;
        let rpm = window.read32(0xd00);
        if rpm == u32::MAX || rpm != window.read32(0xd00) {
            return Err(GtError::Unavailable);
        }
        Ok(crate::intel_gpu_user::DeviceFacts {
            revision: self.parts.boot.revision(),
            graphics_version: ip.version,
            graphics_step: ip.step,
            reference_clock: reference_clock(rpm).ok_or(GtError::Unavailable)?,
        })
    }

    /// A current engine counter observation, serialized with reset by the
    /// PCI owner. Clock IDs match NARF clock_gettime; CLOCK_TAI is unavailable.
    pub fn engine_cycles(
        &mut self,
        engine: crate::intel_gpu_engine::Engine,
        clock: i32,
    ) -> Result<crate::intel_gpu_timestamp::EngineCycles, GtError> {
        if self.user_epoch().is_none()
            || !self
                .engines()
                .is_some_and(|engines| engines.contains(engine))
        {
            return Err(GtError::State);
        }
        if !matches!(clock, 0 | 1 | 4 | 7) {
            return Err(GtError::Unavailable);
        }
        if let Err(error) = self.awake() {
            self.state = GtState::Lost;
            return Err(error);
        }
        crate::intel_gpu_timestamp::sample(
            self.parts.boot.window(),
            engine,
            if self.parts.boot.platform().is_xe2() {
                64
            } else {
                36
            },
            || {
                if clock == 0 {
                    narf_time::now_wall().as_nanos() as u64
                } else {
                    narf_time::monotonic_ns()
                }
            },
            narf_time::monotonic_ns,
        )
        .map_err(|error| match error {
            crate::intel_gpu_timestamp::SampleError::Unavailable => GtError::Unavailable,
            crate::intel_gpu_timestamp::SampleError::Unstable => GtError::Busy,
        })
    }

    pub(crate) fn topology_for_device(
        &mut self,
        device_id: u16,
    ) -> Result<Arc<GtTopology>, GtError> {
        // Validate this live owner even on pre-XeHP families whose firmware
        // has no HWCONFIG table. The fuse snapshot is independently acquired.
        if self.parts.boot.platform().has_hwconfig() {
            self.hwconfig_for_device(device_id)?;
        } else {
            if !matches!(
                self.state,
                GtState::Ready | GtState::CtReady | GtState::SchedulingReady
            ) || self.parts.boot.device_id() != device_id
            {
                return Err(GtError::Boot(BootError::Device));
            }
            self.awake()?;
        }
        self.parts.topology.clone().ok_or(GtError::State)
    }

    /// Only a live, awake owner may supply a card's first discovery snapshot.
    /// The PCI owner still binds the card and GT to the same physical function;
    /// matching a device ID alone cannot distinguish identical PCI functions.
    pub(crate) fn hwconfig_for_device(
        &mut self,
        device_id: u16,
    ) -> Result<Arc<HardwareConfig>, GtError> {
        if !matches!(
            self.state,
            GtState::Ready | GtState::CtReady | GtState::SchedulingReady
        ) {
            return Err(GtError::State);
        }
        if let Err(error) = self.awake() {
            self.state = GtState::Lost;
            return Err(error);
        }
        self.parts
            .boot
            .hwconfig_for_device(device_id)
            .ok_or(GtError::Boot(BootError::Device))
    }

    pub fn has_hwconfig(&self) -> bool {
        self.parts.boot.platform().has_hwconfig()
    }

    /// Issue the zero-address size query before CT owns the MMIO mailbox.
    /// Exactly one table may be acquired per bootstrap lifetime.
    pub fn begin_hwconfig(&mut self, now: u64) -> Result<(), GtError>
    where
        M: Clone,
    {
        if self.state != GtState::Ready || self.parts.ct.is_some() || self.hwconfig().is_some() {
            return Err(GtError::State);
        }
        if let Err(error) = self.awake() {
            self.state = GtState::Lost;
            return Err(error);
        }
        if !self.has_hwconfig() {
            return Err(GtError::Unavailable);
        }
        let mut mailbox = Mailbox::new(self.parts.boot.window().clone());
        if let Err(error) = mailbox.begin(&[0x4100, 0, 0, 0], now) {
            return Err(GtError::Transport(error));
        }
        self.parts.discovery_mailbox = Some(mailbox);
        self.state = GtState::SizingHwconfig;
        Ok(())
    }

    fn read_ack(&self) -> Result<u32, GtError> {
        let reg = self
            .parts
            .boot
            .platform()
            .guc_forcewake_ack()
            .ok_or(GtError::State)?;
        let ack = self.parts.boot.window().read32(reg);
        if ack == u32::MAX {
            Err(GtError::Unavailable)
        } else {
            Ok(ack & 1)
        }
    }

    fn request(&mut self, wake: bool, now: u64) -> Result<(), GtError> {
        self.deadline = now.checked_add(WAKE_NS).ok_or(GtError::WakeTimeout)?;
        self.requested = wake;
        let window = self.parts.boot.window();
        // Mask only the kernel bit. Firmware/user requestors are preserved.
        window.write32(REQUEST, if wake { 0x00010001 } else { 0x00010000 });
        let _ = window.read32(REQUEST);
        Ok(())
    }

    fn awake(&self) -> Result<(), GtError> {
        let request = self.parts.boot.window().read32(REQUEST);
        if request == u32::MAX {
            return Err(GtError::Unavailable);
        }
        if !self.requested || request & 1 == 0 || self.read_ack()? == 0 {
            return Err(GtError::WakeLost);
        }
        for domain in (1..13).filter(|domain| self.media_wells & 1 << domain != 0) {
            let (request, ack) = crate::intel_gpu_gt::media::domain_registers(domain);
            let (request, ack) = (
                self.parts.boot.window().read32(request),
                self.parts.boot.window().read32(ack),
            );
            if request == u32::MAX || ack == u32::MAX {
                return Err(GtError::Unavailable);
            }
            if request & 1 == 0 || ack & 1 == 0 {
                return Err(GtError::WakeLost);
            }
        }
        if !matches!(
            self.state,
            GtState::Recovering
                | GtState::RecoveringRender
                | GtState::PreparingHardware
                | GtState::ReleasingRender
        ) {
            if let Some(hw) = self.hardware.as_ref().filter(|hw| hw.ready()) {
                hw.awake(self.parts.boot.window())
                    .map_err(GtError::Hardware)?;
            }
        }
        Ok(())
    }

    /// Raw physical CCS fuse mask and immutable requested mode. A clean
    /// same-epoch resume must preserve both, even if its selected set matches.
    pub fn compute_configuration(&self) -> Option<(u8, u8)> {
        (self.state == GtState::SchedulingReady)
            .then_some(self.compute_configuration)
            .flatten()
    }

    fn verify_register_policy(&self) -> Result<(), GtError> {
        let engines = self
            .engines()
            .unwrap_or(crate::intel_gpu_engine::EngineSet::of(&[
                crate::intel_gpu_engine::Engine::Rcs0,
                crate::intel_gpu_engine::Engine::Bcs0,
            ]));
        if let Some((mask, mode)) = self.compute_configuration {
            if let Some(expected) = crate::intel_gpu_engine::ccs_mode(mask, mode) {
                for (offset, bits, expected) in
                    [(0x14800, 2, 2), (0x14804, 0xfff, expected & 0xfff)]
                {
                    let value = self.parts.boot.window().read32(offset);
                    if value == u32::MAX {
                        return Err(GtError::Unavailable);
                    }
                    if value & bits != expected {
                        return Err(GtError::Registers(RegisterError::Verify(offset)));
                    }
                }
            }
        }
        let media = matches!(
            self.parts.boot.role(),
            crate::intel_gpu_guc_boot::GuCRole::Media(_)
        );
        let policy = if self.parts.boot.platform().is_headless_integrated() || media {
            self.engine_policy
                .ok_or(GtError::State)
                .map_err(|_| RegisterError::Identity)
        } else {
            EnginePolicy::new(self.parts.boot.platform(), engines)
        };
        policy
            .and_then(|policy| policy.verify(self.parts.boot.window()))
            .map_err(GtError::Registers)
    }

    fn admit_scheduling(&mut self) -> Result<(), GtError> {
        if self.state != GtState::SchedulingReady {
            return Err(GtError::State);
        }
        let result = self
            .awake()
            .and_then(|()| self.current_region())
            .and_then(|()| self.verify_register_policy());
        if result.is_err() && !matches!(result, Err(GtError::Busy)) {
            self.state = GtState::Lost;
        }
        result
    }

    /// Requires exclusive physical-function graphics-GT ownership and a
    /// runtime-PM hold. Never steals a preexisting kernel wake request.
    pub fn begin(&mut self, now: u64) -> Result<(), GtError> {
        if self.state != GtState::Staged {
            return Err(GtError::State);
        }
        let request = self.parts.boot.window().read32(REQUEST);
        if request == u32::MAX {
            return Err(GtError::Unavailable);
        }
        if request & 1 != 0 || self.read_ack()? != 0 {
            return Err(GtError::Busy);
        }
        self.request(true, now)?;
        self.state = GtState::Waking;
        Ok(())
    }

    /// Allocate/register exactly one CT owned by this GT. Allocation refusal
    /// (including noncoherent discrete memory) leaves the ready GuC intact.
    pub fn begin_ct(&mut self, now: u64) -> Result<(), GtError>
    where
        M: Clone,
        A: Clone,
    {
        if self.state != GtState::Ready || self.parts.ct.is_some() {
            return Err(GtError::State);
        }
        if let Err(error) = self.awake() {
            self.state = GtState::Lost;
            return Err(error);
        }
        self.parts.ct = Some(
            self.parts
                .boot
                .allocate_transport()
                .map_err(GtError::Boot)?,
        );
        self.state = GtState::EnablingCt;
        if let Err(error) = self.parts.boot.invalidate_ggtt_before_ct() {
            self.state = GtState::Lost;
            return Err(GtError::Boot(error));
        }
        if let Err(error) = self.parts.ct.as_mut().expect("owned CT").begin_enable(now) {
            self.state = GtState::Lost;
            return Err(GtError::Transport(error));
        }
        Ok(())
    }

    fn start_reset(&mut self, now: u64) -> Result<(), GtError> {
        // Stop observation first; a busy MCR semaphore is retried by poll,
        // with all DMA owners retained and wake still held.
        if self.parts.eu_stall.is_some() && self.parts.boot.state() != BootState::Stopping {
            self.deadline = now.saturating_add(WAKE_NS);
            self.state = GtState::Stopping;
            return Ok(());
        }
        if self.parts.boot.state() != BootState::Stopping {
            self.parts.boot.begin_stop(now).map_err(GtError::Boot)?;
        }
        self.state = GtState::Stopping;
        Ok(())
    }

    /// Cancel admission, recover wake if necessary, then reset GuC. This
    /// also retires partial/poisoned CT registrations without trusting a
    /// late mailbox reply. The owner never resumes after verified stop.
    pub fn begin_stop(&mut self, now: u64) -> Result<(), GtError> {
        if matches!(
            self.state,
            GtState::Staged
                | GtState::Stopped
                | GtState::Recovering
                | GtState::RecoveringRender
                | GtState::Stopping
                | GtState::ResettingEngines
                | GtState::ReleasingRender
                | GtState::Releasing
                | GtState::StoppingMert
                | GtState::StoppingGen12Cs
                | GtState::ReleasingGen12Media
        ) {
            return Err(GtError::State);
        }
        if let Some(scheduler) = self.parts.scheduler.as_mut() {
            scheduler.huc.invalidate();
        }
        // Close admission before any fallible reset/recovery operation.
        self.log_stream.take();
        if let Some(collector) = self.parts.eu_stall.as_mut() {
            collector.invalidate();
        }
        if let Some(mert) = &mut self.parts.mert {
            mert.closing();
        }
        self.state = GtState::Lost;
        self.parts.boot.cancel_reload();
        if matches!(
            self.parts.boot.state(),
            BootState::Staged | BootState::Stopped
        ) {
            return self.after_boot_stop(now);
        }
        match self.awake() {
            Ok(()) => return self.start_reset(now),
            Err(GtError::WakeLost | GtError::Hardware(HardwareError::WakeLost)) => {}
            Err(error) => return Err(error),
        }
        // No DMA memory is reclaimed while recovering a dropped wake ACK.
        self.request(true, now)?;
        self.state = GtState::Recovering;
        Ok(())
    }

    pub fn begin_scheduling(&mut self, now: u64) -> Result<(), GtError>
    where
        A: Clone,
    {
        self.begin_scheduling_with_ccs_mode(now, 1)
    }

    /// Immutable compute partition for this scheduling incarnation. The reset
    /// owner must use the same requested mode and verified fuse identity on
    /// every resume; no client may change an already published engine set.
    pub fn begin_scheduling_with_ccs_mode(&mut self, now: u64, mode: u8) -> Result<(), GtError>
    where
        A: Clone,
    {
        if self.state != GtState::Ready
            || self.parts.ct.is_some()
            || self.hardware.is_none()
            || (self.has_hwconfig() && self.hwconfig().is_none())
        {
            return Err(GtError::State);
        }
        if let Err(error) = self.awake() {
            self.state = GtState::Lost;
            return Err(error);
        }
        if !self.topology().is_some_and(GtTopology::has_render) {
            return Err(GtError::Topology(TopologyError::NoRender));
        }
        let registers = RegisterInit::with_ccs_mode(
            self.parts.boot.window(),
            self.parts.boot.platform(),
            self.parts.boot.device_id(),
            self.topology().ok_or(GtError::State)?,
            self.hwconfig(),
            now,
            mode,
        )
        .map_err(GtError::Registers)?;
        self.mert_required = registers.mert_required();
        let mut scheduler = self
            .parts
            .boot
            .scheduler(registers.engines())
            .map_err(GtError::Boot)?;
        scheduler
            .set_reset_policy(registers.reset_policy().ok_or(GtError::State)?)
            .map_err(GtError::Scheduling)?;
        self.parts.scheduler = Some(scheduler);
        self.compute_configuration = Some(registers.compute_configuration());
        self.engine_policy = Some(registers.engine_policy().map_err(GtError::Registers)?);
        self.registers = Some(registers);
        self.state = GtState::PreparingScheduling;
        Ok(())
    }

    pub fn submit_kernel_probe(
        &mut self,
        now: u64,
    ) -> Result<(u16, Arc<crate::intel_gpu_fence::CompletionFence>), GtError> {
        self.admit_scheduling()?;
        self.parts
            .scheduler
            .as_mut()
            .expect("owned scheduler")
            .submit_probe(now)
            .map_err(GtError::Scheduling)
    }

    /// Seed and save a default RCS0 context, force a different context to run,
    /// then publish the retired image. No external submission is admitted while
    /// the returned fence is pending. Dropping its waiter never cancels DMA.
    /// The owner must keep driving `poll`; the fence does not drive the GT.
    pub fn begin_context_defaults(
        &mut self,
        now: u64,
    ) -> Result<Arc<crate::intel_gpu_fence::CompletionFence>, GtError> {
        self.admit_scheduling()?;
        if !self
            .parts
            .scheduler
            .as_ref()
            .expect("owned scheduler")
            .can_prime()
        {
            return Err(GtError::Busy);
        }
        let seed = crate::intel_gpu_context::ContextSeed::read(
            self.parts.boot.window(),
            self.parts.boot.platform(),
            self.topology().ok_or(GtError::State)?,
            self.hwconfig(),
        )
        .map_err(|error| GtError::Scheduling(SchedulingError::Defaults(error)))?;
        // Revalidate current authority, wake holds and policy after fuse reads.
        self.admit_scheduling()?;
        self.parts
            .scheduler
            .as_mut()
            .expect("owned scheduler")
            .begin_defaults(seed, now)
            .map_err(GtError::Scheduling)
    }

    pub fn context_defaults_ready(&self) -> bool {
        self.state == GtState::SchedulingReady
            && self
                .parts
                .scheduler
                .as_ref()
                .is_some_and(GuCScheduler::defaults_ready)
    }

    pub fn user_epoch(&self) -> Option<u64> {
        (self.state == GtState::SchedulingReady)
            .then(|| self.parts.scheduler.as_ref()?.user_epoch())
            .flatten()
    }

    /// Start GuC SLPC/GUCRC. Optional: errors leave scheduling untouched.
    pub fn begin_slpc(&mut self, now: u64) -> Result<(), GtError> {
        self.admit_scheduling()?;
        let limits = crate::intel_gpu_slpc::Limits::read(
            self.parts.boot.window(),
            self.parts.boot.platform(),
            self.parts.boot.device_id(),
        )
        .map_err(|error| GtError::Scheduling(SchedulingError::Slpc(error)))?;
        self.admit_scheduling()?;
        let parts = &mut *self.parts;
        parts
            .scheduler
            .as_mut()
            .ok_or(GtError::State)?
            .begin_slpc(parts.ct.as_mut().ok_or(GtError::State)?, limits, now)
            .map_err(GtError::Scheduling)
    }

    pub fn slpc(&self) -> crate::intel_gpu_guc_sched::SlpcState {
        self.parts
            .scheduler
            .as_ref()
            .map_or(crate::intel_gpu_guc_sched::SlpcState::Off, |s| s.slpc())
    }

    /// Confirmed frequency bounds/profile only while SLPC is ready. An
    /// in-flight or failed multi-command update has no publishable snapshot.
    pub fn slpc_status(&self) -> Option<crate::intel_gpu_slpc::Status> {
        (self.state == GtState::SchedulingReady)
            .then(|| self.parts.scheduler.as_ref()?.slpc_status())
            .flatten()
    }

    /// Post-probe BMG20.01 PF sanitize. Bootstrap limits remain in force
    /// until actual frequency, host-L2 and initial invalidation are proven.
    /// Keep polling under the reset/PM owner before publishing user admission.
    pub(crate) fn prepare_mert(
        &mut self,
        now: u64,
        mut current: impl FnMut() -> bool,
    ) -> Result<bool, GtError> {
        use crate::intel_gpu_slpc::{mert, SlpcState};
        let map = |error| GtError::Scheduling(SchedulingError::Slpc(error));
        if self.parts.boot.platform() != GtPlatform::Battlemage || self.hardware.is_none() {
            return Ok(true);
        }
        if !current() {
            return Err(GtError::Unavailable);
        }
        self.admit_scheduling()?;
        let epoch = self.user_epoch().ok_or(GtError::State)?;
        if self.parts.mert.is_none() {
            if !mert::qualified(self.parts.boot.window(), &mut current).map_err(map)? {
                return Ok(true);
            }
            self.mert_required = true;
            match self.slpc() {
                SlpcState::Off | SlpcState::Unavailable => {
                    return Err(map(crate::intel_gpu_slpc::SlpcError::Unavailable));
                }
                SlpcState::Running => {}
                _ => return Ok(false),
            }
            let limits = self.slpc_status().ok_or(GtError::State)?.limits;
            self.parts.mert = Some(mert::Mert::new(limits, epoch, now).map_err(map)?);
        }
        let parts = &mut *self.parts;
        let owner = parts.mert.as_mut().expect("MERT owner");
        match owner.prepare(parts.boot.window(), now, epoch, &mut current) {
            Poll::Pending => return Ok(false),
            Poll::Ready(result) => result.map_err(map)?,
        }
        if !owner.sanitizing() {
            let status = parts
                .scheduler
                .as_ref()
                .and_then(|s| s.slpc_status())
                .ok_or(GtError::State)?;
            if status.limits.max_mhz < status.limits.rp0_mhz {
                parts
                    .scheduler
                    .as_mut()
                    .expect("scheduler")
                    .lift_mert_cap(now)
                    .map_err(GtError::Scheduling)?;
            }
            owner.mark_sanitizing();
        }
        Ok(matches!(
            self.slpc(),
            SlpcState::Running | SlpcState::Unavailable
        ))
    }

    /// Exercise raw flush-ticket ownership without a CPU-clear lease.
    /// Production CPU clears must retain their target before any BAR write.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn begin_vram_flush(&mut self, epoch: u64, now: u64) -> Result<u64, GtError> {
        if epoch == 0 || self.user_epoch() != Some(epoch) {
            return Err(GtError::State);
        }
        let Some(owner) = &mut self.parts.mert else {
            return if self.mert_required {
                Err(GtError::State)
            } else {
                Ok(0)
            };
        };
        owner
            .request_flush(epoch, now)
            .map_err(|error| GtError::Scheduling(SchedulingError::Slpc(error)))
    }

    /// Reserve the single retained CPU-write transaction before its first
    /// BAR store. Busy callers have not written and may safely be cancelled.
    /// The caller transfers its PM hold to the returned completion fence.
    pub(crate) fn retain_cpu_vram_clear(
        &mut self,
        object: Arc<crate::intel_gpu_gem::GemObject>,
        epoch: u64,
        now: u64,
    ) -> Result<Option<crate::intel_gpu_slpc::mert::CpuClearLease>, GtError> {
        self.vram_access(epoch)?;
        if epoch == 0 || self.user_epoch() != Some(epoch) {
            return Err(GtError::State);
        }
        let Some(owner) = &mut self.parts.mert else {
            return if self.mert_required {
                Err(GtError::State)
            } else {
                Ok(None)
            };
        };
        owner
            .retain_cpu_clear(object, epoch, now)
            .map(Some)
            .map_err(|error| GtError::Scheduling(SchedulingError::Slpc(error)))
    }

    pub(crate) fn vram_flush_done(&self, epoch: u64, id: u64) -> Result<bool, GtError> {
        if epoch == 0 || self.user_epoch() != Some(epoch) {
            return Err(GtError::State);
        }
        let Some(owner) = &self.parts.mert else {
            return if id == 0 && !self.mert_required {
                Ok(true)
            } else {
                Err(GtError::State)
            };
        };
        owner
            .flush_done(epoch, id)
            .map_err(|error| GtError::Scheduling(SchedulingError::Slpc(error)))
    }

    /// Begin a bounded update; the owner must keep driving `poll` until SLPC
    /// returns Running or Unavailable. Acceptance is not a firmware ACK.
    pub fn begin_slpc_frequency_range(
        &mut self,
        range: crate::intel_gpu_slpc::FrequencyRange,
        now: u64,
    ) -> Result<(), GtError> {
        self.admit_scheduling()?;
        self.parts
            .scheduler
            .as_mut()
            .ok_or(GtError::State)?
            .slpc_frequency_range(range, now)
            .map_err(GtError::Scheduling)
    }

    pub fn begin_slpc_power_profile(
        &mut self,
        profile: crate::intel_gpu_slpc::PowerProfile,
        now: u64,
    ) -> Result<(), GtError> {
        self.admit_scheduling()?;
        self.parts
            .scheduler
            .as_mut()
            .ok_or(GtError::State)?
            .slpc_power_profile(profile, now)
            .map_err(GtError::Scheduling)
    }

    /// SchedulingReady with no registered, running or retiring context.
    pub fn idle(&self) -> bool {
        self.state == GtState::SchedulingReady
            && self
                .parts
                .mert
                .as_ref()
                .is_none_or(|owner| owner.flush_idle())
            && self.log_stream.is_none()
            && self
                .parts
                .eu_stall
                .as_ref()
                .is_none_or(|collector| collector.idle())
            && self
                .parts
                .scheduler
                .as_ref()
                .is_some_and(GuCScheduler::idle)
    }

    /// Runtime resume after a clean idle stop: keep the parked user epoch so
    /// saved contexts continue instead of being treated as reset losses.
    pub fn adopt_user_epoch(&mut self, epoch: u64) -> Result<(), GtError> {
        if self.state != GtState::SchedulingReady {
            return Err(GtError::State);
        }
        self.parts
            .scheduler
            .as_mut()
            .ok_or(GtError::State)?
            .adopt_epoch(epoch)
            .map_err(GtError::Scheduling)
    }

    pub fn submission_version(&self) -> (u8, u8, u8) {
        self.parts.boot.submission_version()
    }

    /// Submit an untrusted, nonsecure PPGTT batch. Unlike the trusted kernel
    /// API, CPU aliases and nested commands are untrusted throughout execution.
    /// Hardware command checking cannot reach the GGTT ring/image/table graph.
    pub fn submit_user_batch(
        &mut self,
        now: u64,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
    ) -> Result<(u16, Arc<crate::intel_gpu_fence::CompletionFence>), GtError> {
        self.submit_user_inner(now, context, batch, None)
    }

    pub fn submit_user_batch_with_output(
        &mut self,
        now: u64,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: &crate::intel_gpu_user::UserOutput<'_>,
    ) -> Result<(u16, Arc<crate::intel_gpu_fence::CompletionFence>), GtError> {
        self.submit_user_inner(now, context, batch, Some(output))
    }

    fn submit_user_inner(
        &mut self,
        now: u64,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: Option<&crate::intel_gpu_user::UserOutput<'_>>,
    ) -> Result<(u16, Arc<crate::intel_gpu_fence::CompletionFence>), GtError> {
        self.admit_scheduling()?;
        self.parts
            .scheduler
            .as_mut()
            .ok_or(GtError::State)?
            .submit_user(now, context, batch, output)
            .map_err(GtError::Scheduling)
    }

    /// Queue a trusted kernel PPGTT batch, retaining its tables and every BO
    /// through verified retirement or full-engine reset.
    ///
    /// # Safety
    /// Every instruction (including nested batches) must be trusted kernel
    /// code, access only its resident mappings and return with BB_END. It must
    /// not alter GGTT, page tables, rings, register access policy, context/transport state or completion
    /// evidence. No CPU mapping or peer may write the objects before terminal
    /// completion. Default 3D state/isolation is not established by this API.
    pub unsafe fn submit_kernel_batch(
        &mut self,
        now: u64,
        batch: crate::intel_gpu_exec::ResidentBatch,
    ) -> Result<(u16, Arc<crate::intel_gpu_fence::CompletionFence>), GtError> {
        self.admit_scheduling()?;
        // SAFETY: forwarded caller contract; the exclusive GT owns CT/reset.
        unsafe {
            self.parts
                .scheduler
                .as_mut()
                .expect("owned scheduler")
                .submit_resident(now, batch)
                .map_err(GtError::Scheduling)
        }
    }

    /// Exercise two private PPGTT BOs with an owned, fixed kernel store batch.
    /// The returned result can be checked after its terminal fence succeeds.
    pub fn submit_ppgtt_probe(
        &mut self,
        now: u64,
    ) -> Result<crate::intel_gpu_exec::PpgttProbeSubmission, GtError> {
        self.submit_ppgtt_probe_on(now, crate::intel_gpu_engine::Engine::Rcs0)
    }

    /// Verify the private store batch on the exact published engine. BMG
    /// COPY1 must execute its own PPGTT probe before backend publication.
    pub(crate) fn submit_ppgtt_probe_on(
        &mut self,
        now: u64,
        engine: crate::intel_gpu_engine::Engine,
    ) -> Result<crate::intel_gpu_exec::PpgttProbeSubmission, GtError> {
        if self.state != GtState::SchedulingReady
            || !self
                .engines()
                .is_some_and(|engines| engines.contains(engine))
        {
            return Err(GtError::State);
        }
        self.admit_scheduling()?;
        let (batch, result) =
            crate::intel_gpu_exec::PpgttProbeResult::prepare(self.parts.boot.platform())
                .map_err(|error| GtError::Scheduling(SchedulingError::Residency(error)))?;
        // SAFETY: both BOs are private, unexported and inaccessible for writes;
        // only the fixed MI_STORE_DATA_IMM/BB_END stream is executable.
        let (id, completion) = unsafe {
            self.parts
                .scheduler
                .as_mut()
                .expect("owned scheduler")
                .submit_resident_on(now, engine, batch)
                .map_err(GtError::Scheduling)?
        };
        Ok(crate::intel_gpu_exec::PpgttProbeSubmission {
            context_id: id,
            completion,
            result,
        })
    }

    /// Full physical-GT startup. The caller retains this owner across every
    /// await, including cancellation or failure; no IRQ-safe guard is held.
    pub async fn start_hardware(&mut self) -> Result<(), GtError>
    where
        M: Clone,
        A: Clone,
    {
        if self.hardware.is_none() {
            return Err(GtError::State);
        }
        self.begin(narf_time::monotonic_ns())?;
        self.wait().await?;
        if self.has_hwconfig() {
            self.begin_hwconfig(narf_time::monotonic_ns())?;
            self.wait().await?;
        }
        self.begin_scheduling(narf_time::monotonic_ns())?;
        self.wait().await?;
        self.begin_ct(narf_time::monotonic_ns())?;
        if self.wait().await? != GtState::SchedulingReady {
            return Err(GtError::State);
        }
        Ok(())
    }

    fn release_wake(&mut self, now: u64) -> Result<(), GtError> {
        if self.parts.boot.platform().is_headless_integrated() {
            self.parts.boot.retire_ggtt().map_err(GtError::Boot)?;
        }
        if self
            .gen12_reset
            .as_ref()
            .is_some_and(|reset| !reset.released())
        {
            return Err(GtError::State);
        }
        if self
            .parts
            .mert
            .as_ref()
            .is_some_and(|owner| !owner.stopped())
        {
            return Err(GtError::State);
        }
        if let Some(hw) = &mut self.hardware {
            hw.begin_release(self.parts.boot.window(), now)
                .map_err(GtError::Hardware)?;
            self.state = GtState::ReleasingRender;
        } else {
            self.request(false, now)?;
            self.state = GtState::Releasing;
        }
        Ok(())
    }

    fn retire_ct(&mut self) {
        if let Some(ct) = self.parts.ct.take() {
            // SAFETY: GuCBoot proved MIA in reset and firmware DMA idle.
            unsafe { ct.release_after_reset() };
        }
    }

    fn after_boot_stop(&mut self, now: u64) -> Result<(), GtError> {
        if self.parts.boot.platform().is_gen12() {
            if self
                .gen12_reset
                .as_ref()
                .is_none_or(|reset| reset.released())
            {
                // The inherited-reset attempt may already own media wake
                // bits when boot never started. Transfer, never duplicate
                // or forget that uncertain request ownership.
                if let Some(reset) = self
                    .hardware
                    .as_mut()
                    .and_then(HardwareInit::take_gen12_reset)
                {
                    self.gen12_reset = Some(reset);
                }
            }
            if let Some(reset) = &mut self.gen12_reset {
                reset.restart(now).map_err(GtError::Hardware)?;
            } else {
                self.gen12_reset = Some(
                    crate::intel_gpu_gt::gen12::reset::Reset::new(now)
                        .map_err(GtError::Hardware)?,
                );
            }
            self.state = GtState::StoppingGen12Cs;
            return Ok(());
        }
        if self.parts.scheduler.is_some() || self.parts.mert.is_some() {
            // xe_gt.c::do_gt_reset brackets a media GRDOM_FULL with
            // Wa_14015076503 while GSC firmware is loaded. NARF never loads
            // GSC firmware and admits media scheduling only without it; a
            // GSC load that appears later keeps this owner retained instead.
            if matches!(
                self.parts.boot.role(),
                crate::intel_gpu_guc_boot::GuCRole::Media(_)
            ) && crate::intel_gpu_gt::media::gsc_firmware_loaded(self.parts.boot.window())?
            {
                return Err(GtError::State);
            }
            self.deadline = now.checked_add(5_000_000).ok_or(GtError::State)?;
            self.parts.boot.window().write32(0x941c, 1);
            let _ = self.parts.boot.window().read32(0x941c);
            self.state = GtState::ResettingEngines;
            return Ok(());
        }
        self.retire_ct();
        self.release_wake(now)
    }

    fn engine_stop_complete(&mut self, now: u64) -> Result<(), GtError> {
        // Full Gen12 engine reset and media ACK release have retired HuC.
        self.parts.boot.huc_full_reset_complete();
        if let Some(collector) = self.parts.eu_stall.take() {
            // SAFETY: GuC reset/DMA idle and GRDOM_FULL self-clear
            // precede release of all observation GGTT storage.
            unsafe { collector.release_after_reset() };
        }
        if let Some(scheduler) = self.parts.scheduler.take() {
            // SAFETY: GuC reset/DMA idle preceded GRDOM_FULL self-clear.
            // Admission is closed and no child scheduler escapes.
            unsafe { scheduler.release_after_reset() };
        }
        self.retire_ct();
        if let Some(mert) = &mut self.parts.mert {
            let map = |error| GtError::Scheduling(SchedulingError::Slpc(error));
            mert.after_reset(now).map_err(map)?;
            self.state = GtState::StoppingMert;
            return Ok(());
        }
        self.release_wake(now)?;
        Ok(())
    }

    pub fn poll(&mut self, now: u64) -> Poll<Result<GtState, GtError>> {
        self.poll_with_access(now, || true)
    }

    /// Physical runtime supplies current PCI D0/authority for every new MERT
    /// register operation. Generic callers retain the enclosing D0 contract.
    pub(crate) fn poll_with_access(
        &mut self,
        now: u64,
        mut current: impl FnMut() -> bool,
    ) -> Poll<Result<GtState, GtError>> {
        let region_current = if self.state == GtState::SchedulingReady {
            match self.current_region() {
                Ok(()) => {
                    self.smallbar_busy_deadline = None;
                    true
                }
                Err(GtError::Busy) => {
                    let deadline = *self
                        .smallbar_busy_deadline
                        .get_or_insert(now.saturating_add(50_000_000));
                    if now < deadline && current() {
                        return Poll::Pending;
                    }
                    false
                }
                Err(_) => false,
            }
        } else {
            true
        };
        let result = if current() && region_current {
            self.poll_inner(now, &mut current)
        } else {
            Poll::Ready(Err(GtError::Unavailable))
        };
        if matches!(result, Poll::Ready(Err(_))) && self.state != GtState::Staged {
            self.state = GtState::Lost;
            if let Some(actor) = &mut self.log_stream {
                actor.lost();
            }
            if let Some(collector) = self.parts.eu_stall.as_mut() {
                collector.lost();
            }
        }
        result
    }

    fn poll_inner(
        &mut self,
        now: u64,
        current: &mut impl FnMut() -> bool,
    ) -> Poll<Result<GtState, GtError>> {
        match self.state {
            GtState::Staged => return Poll::Ready(Err(GtError::State)),
            GtState::Lost => return Poll::Ready(Err(GtError::Poisoned)),
            GtState::Stopped => return Poll::Ready(Ok(self.state)),
            GtState::Waking | GtState::Recovering | GtState::Releasing => {
                let ack = self.read_ack()?;
                if now >= self.deadline {
                    return Poll::Ready(Err(GtError::WakeTimeout));
                }
                if ack != u32::from(self.requested) {
                    return Poll::Pending;
                }
                if self.state == GtState::Releasing {
                    self.state = GtState::Stopped;
                    return Poll::Ready(Ok(self.state));
                }
                self.awake()?;
                if self.state == GtState::Recovering {
                    if let Some(hw) = &mut self.hardware {
                        if hw.awake(self.parts.boot.window()).is_err() {
                            hw.recover(self.parts.boot.window(), now)
                                .map_err(GtError::Hardware)?;
                            self.state = GtState::RecoveringRender;
                            return Poll::Pending;
                        }
                    }
                    self.start_reset(now)?;
                } else if let Some(hw) = &mut self.hardware {
                    hw.begin(self.parts.boot.window(), now)
                        .map_err(GtError::Hardware)?;
                    self.state = GtState::PreparingHardware;
                } else {
                    self.parts.boot.begin(now).map_err(GtError::Boot)?;
                    self.state = GtState::Booting;
                }
                return Poll::Pending;
            }
            _ => {}
        }
        self.awake()?;
        match self.state {
            GtState::PreparingScheduling => {
                // The standalone media GT has no RegisterInit: its engine
                // policy was installed and verified by begin_media_scheduling.
                if let Some(registers) = self.registers.as_ref() {
                    match registers.poll(self.parts.boot.window(), now) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => {
                            let registers = result.map_err(GtError::Registers)?;
                            self.vram = registers.and_then(|r| {
                                crate::intel_gpu_vram::VramLayout::from_registers(r).ok()
                            });
                        }
                    }
                } else if self.media_wells == 0 {
                    return Poll::Ready(Err(GtError::State));
                }
                self.awake()?;
                self.registers = None;
                let parts = &mut *self.parts;
                let scheduler = parts.scheduler.as_mut().expect("owned scheduler");
                scheduler
                    .enable_engine(parts.boot.window())
                    .map_err(GtError::Scheduling)?;
                let ads = scheduler.ads();
                parts
                    .boot
                    .begin_scheduling(ads, now)
                    .map_err(GtError::Boot)?;
                self.state = GtState::StartingScheduling;
                return Poll::Pending;
            }
            GtState::PreparingHardware | GtState::RecoveringRender => {
                let policy = match self
                    .hardware
                    .as_mut()
                    .expect("hardware owner")
                    .poll_with_access(self.parts.boot.window(), now, &mut *current)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(GtError::Hardware)?,
                };
                if self.state == GtState::RecoveringRender {
                    self.start_reset(now)?;
                } else {
                    let topology =
                        GtTopology::read(self.parts.boot.window(), self.parts.boot.platform())
                            .map_err(GtError::Topology)?;
                    self.hardware
                        .as_ref()
                        .expect("hardware owner")
                        .awake(self.parts.boot.window())
                        .map_err(GtError::Hardware)?;
                    self.awake()?;
                    self.parts.topology = Some(Arc::new(topology));
                    self.parts
                        .boot
                        .configure_cache(policy)
                        .map_err(GtError::Boot)?;
                    self.parts.boot.begin(now).map_err(GtError::Boot)?;
                    self.state = GtState::Booting;
                }
                return Poll::Pending;
            }
            GtState::ReleasingRender => {
                match self
                    .hardware
                    .as_mut()
                    .expect("hardware owner")
                    .poll_release(self.parts.boot.window(), now)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(GtError::Hardware)?,
                }
                self.request(false, now)?;
                self.state = GtState::Releasing;
                return Poll::Pending;
            }
            GtState::ResettingEngines => {
                let reset = self.parts.boot.window().read32(0x941c);
                if reset == u32::MAX {
                    return Poll::Ready(Err(GtError::Unavailable));
                }
                if now >= self.deadline {
                    return Poll::Ready(Err(GtError::Boot(BootError::Timeout)));
                }
                if reset & 1 != 0 {
                    return Poll::Pending;
                }
                let status = self.parts.boot.window().read32(0xc000);
                let dma = self.parts.boot.window().read32(0xc314);
                if status == u32::MAX || dma == u32::MAX {
                    return Poll::Ready(Err(GtError::Unavailable));
                }
                if status & 1 == 0 || dma & 1 != 0 {
                    return Poll::Pending;
                }
                if let Some(reset) = &mut self.gen12_reset {
                    // SAFETY: GRDOM_FULL self-clear, GuC reset and firmware
                    // DMA idle were freshly verified above. Keep every DMA
                    // graph/fence and both base wells through media ACK release.
                    unsafe {
                        reset
                            .begin_release_after_full_reset(
                                self.parts.boot.window(),
                                now,
                                &mut *current,
                            )
                            .map_err(GtError::Hardware)?;
                    }
                    self.state = GtState::ReleasingGen12Media;
                } else {
                    self.engine_stop_complete(now)?;
                }
                return Poll::Pending;
            }
            GtState::StoppingGen12Cs => {
                match self
                    .gen12_reset
                    .as_mut()
                    .expect("owned Gen12 reset")
                    .poll_prepare(self.parts.boot.window(), now, &mut *current)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(GtError::Hardware)?,
                }
                self.deadline = now.checked_add(5_000_000).ok_or(GtError::State)?;
                self.parts.boot.window().write32(0x941c, 1);
                if self.parts.boot.window().read32(0x941c) == u32::MAX {
                    return Poll::Ready(Err(GtError::Unavailable));
                }
                self.state = GtState::ResettingEngines;
                return Poll::Pending;
            }
            GtState::ReleasingGen12Media => {
                match self
                    .gen12_reset
                    .as_mut()
                    .expect("owned Gen12 media release")
                    .poll_release(self.parts.boot.window(), now, &mut *current)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map_err(GtError::Hardware)?,
                }
                self.engine_stop_complete(now)?;
                return Poll::Pending;
            }
            GtState::StoppingMert => {
                let parts = &mut *self.parts;
                let mert = parts.mert.as_mut().expect("stopping host-L2 owner");
                match mert.finish_stopped(parts.boot.window(), now, &mut *current) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        result.map_err(|error| GtError::Scheduling(SchedulingError::Slpc(error)))?
                    }
                }
                self.release_wake(now)?;
                return Poll::Pending;
            }
            GtState::SizingHwconfig | GtState::CopyingHwconfig => {
                let response = match self
                    .parts
                    .discovery_mailbox
                    .as_mut()
                    .expect("discovery mailbox")
                    .poll(now)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(GtError::Transport(error))),
                    Poll::Ready(Ok(value)) => value,
                };
                if self.state == GtState::SizingHwconfig {
                    let base = self
                        .parts
                        .boot
                        .prepare_hwconfig(response)
                        .map_err(GtError::Boot)?;
                    self.parts
                        .discovery_mailbox
                        .as_mut()
                        .expect("discovery mailbox")
                        .begin(&[0x4100, base, 0, response], now)
                        .map_err(GtError::Transport)?;
                    self.state = GtState::CopyingHwconfig;
                    return Poll::Pending;
                }
                // As in Linux, any nonnegative copy response is successful;
                // its payload is not a second length negotiation.
                self.parts.boot.finish_hwconfig().map_err(GtError::Boot)?;
                self.state = GtState::Ready;
            }
            GtState::Booting | GtState::StartingScheduling => match self.parts.boot.poll(now) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(GtError::Boot(error))),
                Poll::Ready(Ok(BootState::Ready)) => {
                    if self.state == GtState::StartingScheduling {
                        self.verify_register_policy()?;
                    }
                    self.state = GtState::Ready;
                }
                _ => return Poll::Ready(Err(GtError::State)),
            },
            GtState::EnablingCt => {
                match self
                    .parts
                    .ct
                    .as_mut()
                    .expect("owned CT")
                    .poll_transition(now)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(GtError::Transport(error))),
                    Poll::Ready(Ok(TransportState::Enabled)) => {
                        if self.parts.scheduler.is_some() {
                            self.verify_register_policy()?;
                        }
                        self.state = if self.parts.scheduler.is_some() {
                            GtState::SchedulingReady
                        } else {
                            GtState::CtReady
                        }
                    }
                    _ => return Poll::Ready(Err(GtError::State)),
                }
            }
            GtState::Stopping => {
                if self.parts.boot.state() != BootState::Stopping {
                    let hardware = self.hardware.as_ref();
                    let parts = &mut *self.parts;
                    let platform = parts.boot.platform();
                    if let Some(collector) = parts.eu_stall.as_mut() {
                        let window = parts.boot.window();
                        match collector
                            .disable(window, || observation_awake(window, platform, hardware))
                        {
                            Err(narf_filesystem::FsError::WouldBlock) if now < self.deadline => {
                                return Poll::Pending;
                            }
                            Err(_) => collector.lost(),
                            Ok(()) => {}
                        }
                    }
                    // A lost/stuck steering owner cannot prevent whole-GT
                    // reset escalation. Storage stays retained through GuC
                    // stop, GRDOM_FULL and the existing DMA-idle proofs.
                    self.parts.boot.begin_stop(now).map_err(GtError::Boot)?;
                }
                match self.parts.boot.poll(now) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(GtError::Boot(error))),
                    Poll::Ready(Ok(BootState::Stopped)) => {
                        self.after_boot_stop(now)?;
                        return Poll::Pending;
                    }
                    _ => return Poll::Ready(Err(GtError::State)),
                }
            }
            GtState::Ready | GtState::CtReady => {}
            GtState::SchedulingReady => {
                let parts = &mut *self.parts;
                parts
                    .scheduler
                    .as_mut()
                    .expect("owned scheduler")
                    .poll(parts.ct.as_mut().expect("owned CT"), now)
                    .map_err(GtError::Scheduling)?;
                if let Some(mert) = &mut parts.mert {
                    mert.service_flush(parts.boot.window(), now, &mut *current)
                        .map_err(|error| GtError::Scheduling(SchedulingError::Slpc(error)))?;
                }
            }
            _ => return Poll::Ready(Err(GtError::State)),
        }
        Poll::Ready(Ok(self.state))
    }

    pub async fn wait(&mut self) -> Result<GtState, GtError> {
        self.wait_with_access(|| true).await
    }

    pub(crate) async fn wait_with_access(
        &mut self,
        mut current: impl FnMut() -> bool,
    ) -> Result<GtState, GtError> {
        loop {
            if let Poll::Ready(result) =
                self.poll_with_access(narf_time::monotonic_ns(), &mut current)
            {
                return result;
            }
            // Even if a short timer expires before its first poll, a clock
            // jump or slow MMIO must not monopolize one executor poll.
            narf_scheduler::yield_now().await;
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
        }
    }

    fn ct_ready(&mut self) -> Result<(), GtError> {
        if self.state != GtState::CtReady {
            return Err(GtError::State);
        }
        if let Err(error) = self.awake() {
            self.state = GtState::Lost;
            return Err(error);
        }
        Ok(())
    }

    pub fn send(
        &mut self,
        fence: u16,
        action: u16,
        data0: u16,
        payload: &[u32],
        fast: bool,
    ) -> Result<(), GtError> {
        self.ct_ready()?;
        let ct = self.parts.ct.as_mut().expect("owned CT");
        let result = ct.send(fence, action, data0, payload, fast);
        if ct.state() == TransportState::Lost {
            self.state = GtState::Lost;
        }
        result.map_err(GtError::Transport)
    }

    pub fn receive(&mut self) -> Result<Option<GuCMessage>, GtError> {
        self.ct_ready()?;
        let result = self.parts.ct.as_mut().expect("owned CT").receive();
        if result.is_err() {
            self.state = GtState::Lost;
        }
        result.map_err(GtError::Transport)
    }

    /// # Safety
    /// The PCI owner proved a full GT reset stopped all engines and GuC/firmware
    /// DMA, invalidated stale HWS/LRC/GGTT addresses and released/reset both the
    /// render-well, graphics-GT and every owned Gen12 media kernel wake request.
    /// If MERT host-L2 was exposed, the external owner also proved its manual
    /// requested/actual cap, fresh GLOBAL_INVAL drain and host-L2 disable before
    /// releasing those wells.
    /// Neither unreadable registers nor elapsed time supplies that proof.
    /// Any exposed TGL HuC image additionally requires full media-engine
    /// reset/idle and retained media-wake release, never GuC-only Stopped.
    pub unsafe fn release_after_gt_reset(mut self) {
        self.released = true;
        // SAFETY: consumed once under the caller's full-reset proof.
        let Parts {
            boot,
            ct,
            scheduler,
            eu_stall,
            mert,
            ..
        } = unsafe { ManuallyDrop::take(&mut self.parts) };
        if let Some(mert) = mert {
            // SAFETY: the external proof also covers host-L2 shutdown.
            unsafe { mert.release_after_reset() };
        }
        if let Some(collector) = eu_stall {
            // SAFETY: the caller's full graphics-GT/DMA reset proof covers it.
            unsafe { collector.release_after_reset() };
        }
        if let Some(scheduler) = scheduler {
            // SAFETY: the external full-reset proof covers HWS and engines too.
            unsafe { scheduler.release_after_reset() };
        }
        if let Some(ct) = ct {
            // SAFETY: the caller's proof covers this owned CT allocation.
            unsafe { ct.release_after_reset() };
        }
        // SAFETY: the same proof covers firmware, ADS and logs.
        unsafe { boot.release_after_gt_reset() };
    }
}

impl<W: MmioWindow, A: BootAllocator> GuCGt<crate::intel_gpu_gt::media::MediaGsi<W>, A> {
    /// MTL/Arrow standalone media GuC (GT1). This is the bare GuCGt path:
    /// no render well, MCR, topology, HWCONFIG, MERT or scheduler. Its wake
    /// request/ACK, GuC reset, WOPCM, DMA, ADS and CT all resolve through the
    /// media GSI window and media mailbox. `policy` proves the media PAT that
    /// gives the shared GGTT PTE index its meaning on this GT.
    pub(crate) fn stage_media(
        mmio: crate::intel_gpu_gt::media::MediaGsi<W>,
        allocator: A,
        firmware: &GuCFirmware,
        config: BootConfig,
        ip: crate::intel_gpu_gt::media::MediaIp,
        policy: crate::intel_gpu_gt_hw::CachePolicy,
    ) -> Result<Self, GtError> {
        let mut boot =
            GuCBoot::stage_media(mmio, allocator, firmware, config, ip).map_err(GtError::Boot)?;
        boot.configure_cache(policy).map_err(GtError::Boot)?;
        Ok(Self::from_staged(boot))
    }

    /// Prepare media scheduling on the booted media GuC, before CT. `wells`
    /// are the VDBOX/VEBOX forcewake domains (`media::engine_domains`) whose
    /// kernel wake the caller holds and keeps until this owner is Stopped.
    /// As Linux xe on GT1: engines come from the media fuses, the NONPRIV
    /// whitelist (hwe->reg_whitelist) is applied before ring enable, the ADS
    /// is populated from that list and the GuC reloads with submission
    /// enabled. No HWCONFIG, render well, MCR steering or SLPC is involved.
    pub(crate) fn begin_media_scheduling(
        &mut self,
        engines: crate::intel_gpu_engine::EngineSet,
        wells: u16,
    ) -> Result<(), GtError>
    where
        A: Clone,
    {
        let crate::intel_gpu_guc_boot::GuCRole::Media(_) = self.parts.boot.role() else {
            return Err(GtError::State);
        };
        if self.state != GtState::Ready
            || self.parts.ct.is_some()
            || self.parts.scheduler.is_some()
            || wells == 0
            || wells != crate::intel_gpu_gt::media::engine_domains(engines)
        {
            return Err(GtError::State);
        }
        let platform = self.parts.boot.platform();
        let policy = EnginePolicy::media(platform, engines).map_err(GtError::Registers)?;
        let reset = crate::intel_gpu_reset_policy::ResetPolicy::media(
            platform,
            self.parts.boot.device_id(),
            engines,
        )
        .ok_or(GtError::State)?;
        self.media_wells = wells;
        if let Err(error) = self.awake() {
            self.state = GtState::Lost;
            return Err(error);
        }
        if crate::intel_gpu_gt::media::gsc_firmware_loaded(self.parts.boot.window())? {
            return Err(GtError::Busy);
        }
        let mut scheduler = self.parts.boot.scheduler(engines).map_err(GtError::Boot)?;
        scheduler
            .set_reset_policy(reset)
            .map_err(GtError::Scheduling)?;
        // Engines are idle in the GuC-sanitized GT1 with every well held. An
        // unpublished scheduler is dropped (freed) on refusal.
        policy
            .install(self.parts.boot.window())
            .map_err(GtError::Registers)?;
        self.parts.scheduler = Some(scheduler);
        self.engine_policy = Some(policy);
        self.state = GtState::PreparingScheduling;
        Ok(())
    }

    /// Record GT1's default LRCs: one empty media 13.00 WA job per engine,
    /// switched out and captured. Its fence completes after the last capture.
    pub(crate) fn begin_media_context_defaults(
        &mut self,
        now: u64,
    ) -> Result<Arc<crate::intel_gpu_fence::CompletionFence>, GtError> {
        self.admit_scheduling()?;
        self.parts
            .scheduler
            .as_mut()
            .expect("owned scheduler")
            .begin_media_defaults(now)
            .map_err(GtError::Scheduling)
    }

    /// GT1's own command-streamer timestamp clock (xe_gt_clock.c on the media
    /// GT reads RPM_CONFIG0 through the GSI window).
    pub(crate) fn media_reference_clock(&self) -> Result<u32, GtError> {
        self.awake()?;
        let window = self.parts.boot.window();
        let rpm = window.read32(0xd00);
        if rpm == u32::MAX || rpm != window.read32(0xd00) {
            return Err(GtError::Unavailable);
        }
        reference_clock(rpm).ok_or(GtError::Unavailable)
    }
}

/// xe_gt_clock.c::read_crystal_clock + xe_gt_clock_init: crystal selector
/// [5:3] and the CTC shift [2:1] of RPM_CONFIG0.
fn reference_clock(rpm: u32) -> Option<u32> {
    let crystal: u32 = match (rpm >> 3) & 7 {
        0 => 24_000_000,
        1 => 19_200_000,
        2 => 38_400_000,
        3 => 25_000_000,
        _ => return None,
    };
    Some(crystal >> (3 - ((rpm >> 1) & 3)))
}

impl<M: MmioWindow, A: BootAllocator> GuCGt<M, A> {
    /// A handle to this GT's GGTT allocator, for a second GuC of the same
    /// tile whose firmware memory must come from the same shared GGTT.
    pub(crate) fn shared_allocator(&self) -> A
    where
        A: Clone,
    {
        self.parts.boot.diagnostic_allocator()
    }

    /// Which GuC of the tile this owner boots.
    // Read only by native fixtures.
    #[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
    pub(crate) fn guc_role(&self) -> crate::intel_gpu_guc_boot::GuCRole {
        self.parts.boot.role()
    }
}

impl<M: MmioWindow, A: BootAllocator> Drop for GuCGt<M, A> {
    fn drop(&mut self) {
        if !self.released && matches!(self.state, GtState::Staged | GtState::Stopped) {
            self.released = true;
            // SAFETY: unpublished, or verified GuC/DMA stop followed by wake
            // release acknowledgment. Resources are destroyed exactly once.
            unsafe { ManuallyDrop::drop(&mut self.parts) };
        }
    }
}
