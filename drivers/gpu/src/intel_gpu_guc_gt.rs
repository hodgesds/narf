//! One graphics-GT owner for forcewake, GuC bootstrap and CT memory.
//!
//! Reference: ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! MIT xe_force_wake.c and regs/xe_gt_regs.h, plus xe_guc.c reset protocol.
//! This owner is exclusive, not a refcount shared with the legacy Gen12
//! forcewake manager. The PCI owner supplies runtime-PM and serializes all
//! other reset/firmware users. No userspace submission is admitted here.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt_hw::{HardwareError, HardwareInit};
use crate::intel_gpu_gt_registers::{RegisterError, RegisterInit};
use crate::intel_gpu_guc::GuCMessage;
use crate::intel_gpu_guc_boot::{BootAllocator, BootConfig, BootError, BootState, GuCBoot};
use crate::intel_gpu_guc_firmware::GuCFirmware;
use crate::intel_gpu_guc_sched::{GuCScheduler, SchedulingError};
use crate::intel_gpu_guc_transport::{Mailbox, TransportError, TransportState, XeLpgTransport};
use crate::intel_gpu_hwconfig::HardwareConfig;
use crate::intel_gpu_nonpriv::EnginePolicy;
use crate::intel_gpu_topology::{GtTopology, TopologyError};
use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::task::Poll;

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
    /// Battlemage tile-0 local memory, probed under register steering. A
    /// malformed layout leaves VRAM unpublished, never guessed.
    vram: Option<crate::intel_gpu_vram::VramLayout>,
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
        if firmware.platform() == crate::intel_gpu_gt::GtPlatform::Battlemage
            && config.uncached_mocs != Some(3)
        {
            return Err(GtError::Boot(BootError::Device));
        }
        Self::from_staged_hardware(
            GuCBoot::stage(mmio, allocator, firmware, config).map_err(GtError::Boot)?,
        )
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
            }),
            state: GtState::Staged,
            deadline: 0,
            requested: false,
            released: false,
            hardware: None,
            registers: None,
            vram: None,
        }
    }

    pub fn state(&self) -> GtState {
        self.state
    }

    /// Last validated firmware table. It describes hardware capabilities, not
    /// active engine/fuse masks or permission to admit userspace submissions.
    pub fn hwconfig(&self) -> Option<&HardwareConfig> {
        self.parts.boot.hwconfig()
    }

    pub fn vram_layout(&self) -> Option<crate::intel_gpu_vram::VramLayout> {
        self.vram
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
        let crystal = match (rpm >> 3) & 7 {
            0 => 24_000_000,
            1 => 19_200_000,
            2 => 38_400_000,
            3 => 25_000_000,
            _ => return Err(GtError::Unavailable),
        };
        Ok(crate::intel_gpu_user::DeviceFacts {
            revision: self.parts.boot.revision(),
            graphics_version: ip.version,
            graphics_step: ip.step,
            reference_clock: crystal >> (3 - ((rpm >> 1) & 3)),
        })
    }

    /// A current engine counter observation, serialized with reset by the
    /// PCI owner. Clock IDs match NARF clock_gettime; CLOCK_TAI is unavailable.
    pub fn engine_cycles(
        &mut self,
        engine: crate::intel_gpu_engine::Engine,
        clock: i32,
    ) -> Result<crate::intel_gpu_timestamp::EngineCycles, GtError> {
        if self.user_epoch().is_none() {
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
            if self.parts.boot.platform() == crate::intel_gpu_gt::GtPlatform::Battlemage {
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
        // Reuse the live state, current wake, actual PCI ID and acquired
        // HWCONFIG gate; a numeric PCI ID alone cannot authorize publication.
        self.hwconfig_for_device(device_id)?;
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

    fn verify_register_policy(&self) -> Result<(), GtError> {
        EnginePolicy::new(self.parts.boot.platform())
            .and_then(|policy| policy.verify(self.parts.boot.window()))
            .map_err(GtError::Registers)
    }

    fn admit_scheduling(&mut self) -> Result<(), GtError> {
        if self.state != GtState::SchedulingReady {
            return Err(GtError::State);
        }
        let result = self.awake().and_then(|()| self.verify_register_policy());
        if result.is_err() {
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
        ) {
            return Err(GtError::State);
        }
        // Close admission before any fallible reset/recovery operation.
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
        if self.state != GtState::Ready
            || self.parts.ct.is_some()
            || self.hardware.is_none()
            || self.hwconfig().is_none()
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
        let registers = RegisterInit::new(
            self.parts.boot.window(),
            self.parts.boot.platform(),
            self.parts.boot.device_id(),
            self.topology().ok_or(GtError::State)?,
            self.hwconfig().ok_or(GtError::State)?,
            now,
        )
        .map_err(GtError::Registers)?;
        let scheduler = self.parts.boot.scheduler().map_err(GtError::Boot)?;
        self.parts.scheduler = Some(scheduler);
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
            self.hwconfig().ok_or(GtError::State)?,
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
        if self.state != GtState::SchedulingReady {
            return Err(GtError::State);
        }
        let (batch, result) =
            crate::intel_gpu_exec::PpgttProbeResult::prepare(self.parts.boot.platform())
                .map_err(|error| GtError::Scheduling(SchedulingError::Residency(error)))?;
        // SAFETY: both BOs are private, unexported and inaccessible for writes;
        // only the fixed MI_STORE_DATA_IMM/BB_END stream is executable.
        let (id, completion) = unsafe { self.submit_kernel_batch(now, batch)? };
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
        self.begin_hwconfig(narf_time::monotonic_ns())?;
        self.wait().await?;
        self.begin_scheduling(narf_time::monotonic_ns())?;
        self.wait().await?;
        self.begin_ct(narf_time::monotonic_ns())?;
        if self.wait().await? != GtState::SchedulingReady {
            return Err(GtError::State);
        }
        Ok(())
    }

    fn release_wake(&mut self, now: u64) -> Result<(), GtError> {
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
        if self.parts.scheduler.is_some() {
            self.deadline = now.checked_add(5_000_000).ok_or(GtError::State)?;
            self.parts.boot.window().write32(0x941c, 1);
            let _ = self.parts.boot.window().read32(0x941c);
            self.state = GtState::ResettingEngines;
            return Ok(());
        }
        self.retire_ct();
        self.release_wake(now)
    }

    pub fn poll(&mut self, now: u64) -> Poll<Result<GtState, GtError>> {
        let result = self.poll_inner(now);
        if matches!(result, Poll::Ready(Err(_))) && self.state != GtState::Staged {
            self.state = GtState::Lost;
        }
        result
    }

    fn poll_inner(&mut self, now: u64) -> Poll<Result<GtState, GtError>> {
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
                match self
                    .registers
                    .as_ref()
                    .expect("owned register initialization")
                    .poll(self.parts.boot.window(), now)
                {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        let registers = result.map_err(GtError::Registers)?;
                        self.vram =
                            registers.and_then(|r| crate::intel_gpu_vram::VramLayout::xe2(r).ok());
                    }
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
                    .poll(self.parts.boot.window(), now)
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
                if let Some(scheduler) = self.parts.scheduler.take() {
                    // SAFETY: GuC reset/DMA idle preceded GRDOM_FULL self-clear.
                    // Admission is closed and no child scheduler escapes.
                    unsafe { scheduler.release_after_reset() };
                }
                self.retire_ct();
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
            GtState::Stopping => match self.parts.boot.poll(now) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(GtError::Boot(error))),
                Poll::Ready(Ok(BootState::Stopped)) => {
                    self.after_boot_stop(now)?;
                    return Poll::Pending;
                }
                _ => return Poll::Ready(Err(GtError::State)),
            },
            GtState::Ready | GtState::CtReady => {}
            GtState::SchedulingReady => {
                let parts = &mut *self.parts;
                parts
                    .scheduler
                    .as_mut()
                    .expect("owned scheduler")
                    .poll(parts.ct.as_mut().expect("owned CT"), now)
                    .map_err(GtError::Scheduling)?;
            }
            _ => return Poll::Ready(Err(GtError::State)),
        }
        Poll::Ready(Ok(self.state))
    }

    pub async fn wait(&mut self) -> Result<GtState, GtError> {
        loop {
            if let Poll::Ready(result) = self.poll(narf_time::monotonic_ns()) {
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
    /// render-well and graphics-GT kernel wake requests.
    /// Neither unreadable registers nor elapsed time supplies that proof.
    pub unsafe fn release_after_gt_reset(mut self) {
        self.released = true;
        // SAFETY: consumed once under the caller's full-reset proof.
        let Parts {
            boot,
            ct,
            scheduler,
            ..
        } = unsafe { ManuallyDrop::take(&mut self.parts) };
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
