//! Owned GuC scheduling for kernel GGTT/PPGTT and nonsecure userspace work.
//!
//! Linux reference: ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! MIT xe_guc_submit.c, xe_lrc.c, xe_guc_ads.c and their ABI headers.
//! Scheduling acknowledgments are not job completion. Retirement additionally
//! requires the GPU breadcrumb and exact saved ring head after deregistration.

use crate::intel_gpu_error::{Capture, ContextInfo, ContextPhase, Contexts, Reason, Report};
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_context::{ContextError, ContextSeed},
    intel_gpu_engine::{Engine, EngineSet, BREADCRUMB, REGS},
    intel_gpu_exec::ResidentBatch,
    intel_gpu_fence::{CompletionFence, JobError},
    intel_gpu_gt::GtPlatform,
    intel_gpu_guc::GuCMessage,
    intel_gpu_guc_boot::BootAllocator,
    intel_gpu_guc_transport::{TransportError, XeLpgTransport},
    intel_gpu_rcs::{GpuBacking, SubmitError},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    mem::ManuallyDrop,
    sync::atomic::{fence, Ordering},
};

const TIMEOUT: u64 = 5_000_000_000;
#[path = "intel_gpu_job_timeout.rs"]
mod job_timeout;
#[path = "intel_gpu_parallel.rs"]
mod parallel;
const MAX_CONTEXTS: usize = 64;
pub use crate::intel_gpu_slpc::SlpcState;
use crate::intel_gpu_slpc::{FrequencyRange, Limits, PowerProfile, Slpc, SlpcError, Status};

/// Firmware context identities are reusable after deregistration. Request
/// stamps are independent, so a prior TLB ACK/breadcrumb cannot complete a
/// new incarnation. The final TLB ACK is our reclamation/reuse barrier.
struct Identities {
    used: u64,
    next_id: u16,
    next_stamp: u32,
}
impl Identities {
    const fn new() -> Self {
        Self {
            used: 0,
            next_id: 1,
            next_stamp: 1,
        }
    }
    fn candidate(&self, live: impl Fn(u32) -> bool) -> Result<(u16, u32), SchedulingError> {
        self.candidate_width(1, live)
    }
    fn candidate_width(
        &self,
        width: u16,
        live: impl Fn(u32) -> bool,
    ) -> Result<(u16, u32), SchedulingError> {
        let id = (0..64)
            .map(|n| (self.next_id - 1 + n) % 64 + 1)
            .find(|id| {
                (1..=4).contains(&width)
                    && *id + width - 1 <= 64
                    && (0..width).all(|lane| self.used & (1u64 << (*id + lane - 1)) == 0)
            })
            .ok_or(SchedulingError::Full)?;
        let mut stamp = self.next_stamp;
        while live(stamp) {
            stamp = ((stamp + 1) & 0x7fffffff).max(1);
        }
        Ok((id, stamp))
    }
    fn claim(&mut self, id: u16, stamp: u32) {
        self.used |= 1u64 << (id - 1);
        self.next_id = id % 64 + 1;
        self.next_stamp = ((stamp + 1) & 0x7fffffff).max(1);
    }
    fn retire(&mut self, id: u16) {
        self.used &= !(1u64 << (id - 1));
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedulingError {
    State,
    Busy,
    Full,
    Allocation(SubmitError),
    Address,
    Cache,
    Residency(narf_filesystem::FsError),
    Output(narf_filesystem::InstallFdError),
    Defaults(ContextError),
    Protocol,
    Timeout,
    Transport(TransportError),
    Slpc(SlpcError),
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct EngineAds {
    pub golden: u32,
    pub bytes: u32,
    pub hwsp: u32,
}

/// Indexed by `Engine::index`; exactly the scheduler's engines are present.
#[derive(Copy, Clone, Debug)]
pub(crate) struct SchedulingAds {
    pub engines: [Option<EngineAds>; Engine::COUNT],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Invalidate,
    Invalidating,
    Register,
    Policy,
    Enable,
    Enabling,
    Dispatch,
    Running,
    Disable,
    Disabling,
    Deregister,
    Deregistering,
    RetireInvalidate,
    RetireInvalidating,
}

/// Engines prime in `Engine::ALL` order; one engine's golden image is
/// published before the next engine's seed is admitted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Defaults {
    Empty,
    Seed(Engine, u16),
    Switch(Engine, u16),
    Next(Engine),
    Ready,
}

struct Context<B: GpuBacking> {
    /// Class-compatible template; virtual scheduling does not pin this engine.
    engine: Engine,
    placements: EngineSet,
    id: u16,
    stamp: u32,
    image: B,
    ring: B,
    phase: Phase,
    deadline: u64,
    runtime: job_timeout::Runtime,
    fence: Arc<CompletionFence>,
    resident: Option<ResidentBatch>,
    user: Option<crate::intel_gpu_user::UserJob>,
    tail: u32,
    /// The GPU runtime budget expired: the user job is being taken off
    /// the engine (Linux guc_exec_queue_timedout_job).
    timed_out: bool,
    /// GuC reset the engine under this context (CONTEXT_RESET_NOTIFICATION).
    reset: bool,
    primary_finished: bool,
    parallel: Option<parallel::Group<B>>,
}

impl<B: GpuBacking> Context<B> {
    fn backings(&self) -> impl Iterator<Item = &B> {
        [&self.image, &self.ring]
            .into_iter()
            .chain(self.parallel.iter().flat_map(|group| group.backings()))
    }
    fn width(&self) -> usize {
        self.parallel.as_ref().map_or(1, parallel::Group::width)
    }
    fn all_finished(&self) -> bool {
        self.image.read32(BREADCRUMB) == self.stamp
            && self.image.read32(REGS + 5 * 4) & 0x1ffffc == self.tail
            && self.parallel.as_ref().is_none_or(|group| {
                group.children.iter().all(|lane| {
                    lane.image.read32(BREADCRUMB) == self.stamp
                        && lane.image.read32(REGS + 5 * 4) & 0x1ffffc == lane.tail
                })
            })
    }
    fn child_diagnostics(&self) -> impl Iterator<Item = ContextInfo> + '_ {
        let primary = self.diagnostic();
        self.parallel.iter().flat_map(move |group| {
            group.children.iter().enumerate().map(move |(index, lane)| {
                let mut info = primary;
                info.id = self.id + index as u16 + 1;
                info.engine = Some(lane.engine);
                info.placements = EngineSet::of(&[lane.engine]);
                info.timed_out = self.timed_out && group.timeout_lanes & (1 << (index + 1)) != 0;
                info.reset = self.reset && group.reset_lanes & (1 << (index + 1)) != 0;
                info.observed_runtime_ticks = lane.runtime.diagnostic_ticks();
                info
            })
        })
    }
    fn owns_engine(&self, engine: Engine) -> bool {
        self.placements.contains(engine)
            || self
                .parallel
                .as_ref()
                .is_some_and(|group| group.children.iter().any(|lane| lane.engine == engine))
    }
    fn diagnostic(&self) -> ContextInfo {
        ContextInfo {
            engine: job_timeout::observed_engine(&self.image, self.stamp, self.placements)
                .ok()
                .flatten(),
            placements: self.placements,
            id: self.id,
            request_stamp: self.stamp,
            phase: match self.phase {
                Phase::Invalidate => ContextPhase::Invalidate,
                Phase::Invalidating => ContextPhase::Invalidating,
                Phase::Register => ContextPhase::Register,
                Phase::Policy => ContextPhase::Policy,
                Phase::Enable => ContextPhase::Enable,
                Phase::Enabling => ContextPhase::Enabling,
                Phase::Dispatch => ContextPhase::Enabling,
                Phase::Running => ContextPhase::Running,
                Phase::Disable => ContextPhase::Disable,
                Phase::Disabling => ContextPhase::Disabling,
                Phase::Deregister => ContextPhase::Deregister,
                Phase::Deregistering => ContextPhase::Deregistering,
                Phase::RetireInvalidate => ContextPhase::RetireInvalidate,
                Phase::RetireInvalidating => ContextPhase::RetireInvalidating,
            },
            timed_out: self.timed_out
                && self
                    .parallel
                    .as_ref()
                    .is_none_or(|g| g.timeout_lanes & 1 != 0),
            reset: self.reset
                && self
                    .parallel
                    .as_ref()
                    .is_none_or(|g| g.reset_lanes & 1 != 0),
            observed_runtime_ticks: self.runtime.diagnostic_ticks(),
        }
    }
}

struct EngineState<B: GpuBacking> {
    engine: Engine,
    hwsp: B,
    golden: B,
    /// GPU execution progress, independent of CT traffic and queue admission.
    last_progress: Option<u64>,
}

fn state_of<B: GpuBacking>(engines: &[EngineState<B>], engine: Engine) -> &EngineState<B> {
    engines
        .iter()
        .find(|state| state.engine == engine)
        .expect("scheduler engine")
}

struct Resources<A: BootAllocator> {
    allocator: A,
    engines: Vec<EngineState<A::Backing>>,
    contexts: Vec<Context<A::Backing>>,
    seed_image: Option<A::Backing>,
    seed_id: Option<u16>,
    defaults_completion: Option<Arc<CompletionFence>>,
    /// SLPC shared data; GuC may reach it until a proven reset.
    slpc: Option<A::Backing>,
}

pub(crate) struct GuCScheduler<A: BootAllocator> {
    resources: ManuallyDrop<Resources<A>>,
    platform: GtPlatform,
    identities: Identities,
    published: bool,
    lost: bool,
    released: bool,
    defaults: Defaults,
    pristine: bool,
    epoch: u64,
    /// A user job ran under `epoch`; its identity can no longer change.
    user_submitted: bool,
    slpc: Slpc,
    engines: EngineSet,
    /// Default CCS state commands, captured with the render seed's fuses.
    disable_wmtp: bool,
    /// Captured only on an actual failure, before disable can provoke reset.
    pending_error: Option<Report>,
}

impl<A: BootAllocator> GuCScheduler<A> {
    pub(crate) fn allocate(
        mut allocator: A,
        platform: GtPlatform,
        engines: EngineSet,
    ) -> Result<Self, SchedulingError> {
        if !engines.contains(Engine::Rcs0)
            || (platform != GtPlatform::Battlemage && engines.contains(Engine::Bcs8))
        {
            return Err(SchedulingError::State);
        }
        let mut owned: Vec<A::Backing> = Vec::new();
        let release = |allocator: &mut A, owned: Vec<A::Backing>| {
            for backing in owned.into_iter().rev() {
                allocator.free(backing);
            }
        };
        for engine in engines.iter() {
            for pages in [1, engine.lrc_pages(platform)] {
                let backing = match allocator.alloc(pages) {
                    Ok(b) => b,
                    Err(e) => {
                        release(&mut allocator, owned);
                        return Err(SchedulingError::Allocation(e));
                    }
                };
                let error = if !valid(&backing) || backing.size_pages() != pages {
                    Some(SchedulingError::Address)
                } else if !backing.coherent_for_device() {
                    Some(SchedulingError::Cache)
                } else if owned.iter().any(|old| overlap(old, &backing)) {
                    Some(SchedulingError::Address)
                } else {
                    None
                };
                owned.push(backing);
                if let Some(error) = error {
                    release(&mut allocator, owned);
                    return Err(error);
                }
            }
        }
        for backing in &owned {
            backing.zero_fill();
            if allocator.sync_for_device(backing).is_err() {
                release(&mut allocator, owned);
                return Err(SchedulingError::Cache);
            }
        }
        let mut states = Vec::new();
        let mut owned = owned.into_iter();
        for engine in engines.iter() {
            let (hwsp, golden) = (owned.next().expect("HWS"), owned.next().expect("golden"));
            states.push(EngineState {
                engine,
                hwsp,
                golden,
                last_progress: None,
            });
        }
        Ok(Self {
            epoch: crate::intel_gpu_user::next_epoch(),
            resources: ManuallyDrop::new(Resources {
                allocator,
                engines: states,
                contexts: Vec::new(),
                seed_image: None,
                seed_id: None,
                defaults_completion: None,
                slpc: None,
            }),
            platform,
            identities: Identities::new(),
            published: false,
            lost: false,
            released: false,
            defaults: Defaults::Empty,
            pristine: true,
            user_submitted: false,
            slpc: Slpc::new(),
            engines,
            disable_wmtp: false,
            pending_error: None,
        })
    }

    pub(crate) fn ads(&self) -> SchedulingAds {
        let mut engines = [None; Engine::COUNT];
        for state in &self.resources.engines {
            engines[state.engine.index()] = Some(EngineAds {
                golden: state.golden.ggtt_offset(),
                bytes: state.golden.size_pages() * 4096,
                hwsp: state.hwsp.ggtt_offset(),
            });
        }
        SchedulingAds { engines }
    }

    pub(crate) fn engines(&self) -> EngineSet {
        self.engines
    }

    pub(crate) fn diagnostic_contexts(&self) -> Contexts {
        let mut contexts = Contexts::new(self.resources.contexts.iter().map(Context::width).sum());
        // Guilty/reset contexts precede innocent queued contexts if capped.
        for context in self
            .resources
            .contexts
            .iter()
            .filter(|c| c.timed_out || c.reset)
            .chain(
                self.resources
                    .contexts
                    .iter()
                    .filter(|c| !c.timed_out && !c.reset),
            )
            .take(crate::intel_gpu_error::MAX_CONTEXTS)
        {
            contexts.push(context.diagnostic());
            for child in context.child_diagnostics() {
                contexts.push(child);
            }
        }
        contexts
    }

    pub(crate) fn take_error_report(&mut self) -> Option<Report> {
        self.pending_error.take()
    }

    pub(crate) fn enable_engine(&mut self, mmio: &impl MmioWindow) -> Result<(), SchedulingError> {
        if self.published || self.lost {
            return Err(SchedulingError::State);
        }
        if self
            .engines
            .iter()
            .any(|e| mmio.read32(u64::from(e.base()) + 0x8c) == u32::MAX)
        {
            return Err(SchedulingError::Protocol);
        }
        // xe_hw_engine_enable_ring: render-well and GT wake are held by GuCGt.
        self.published = true;
        for state in &self.resources.engines {
            crate::intel_gpu_engine::enable_ring(
                mmio,
                state.engine,
                self.platform,
                state.hwsp.ggtt_offset(),
            );
        }
        Ok(())
    }

    /// Execute only an owned kernel probe. No user commands, PPGTT, external
    /// addresses or arbitrary instructions enter this bring-up API.
    pub(crate) fn submit_probe(
        &mut self,
        now: u64,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        self.admit()?;
        self.submit(now, Engine::Rcs0, None, None)
    }

    fn admit(&self) -> Result<(), SchedulingError> {
        if matches!(
            self.defaults,
            Defaults::Seed(..) | Defaults::Switch(..) | Defaults::Next(_)
        ) {
            return Err(SchedulingError::Busy);
        }
        Ok(())
    }

    pub(crate) fn defaults_ready(&self) -> bool {
        self.defaults == Defaults::Ready && !self.lost
    }

    pub(crate) fn user_epoch(&self) -> Option<u64> {
        (self.published && self.defaults_ready()).then_some(self.epoch)
    }

    pub(crate) fn slpc(&self) -> SlpcState {
        self.slpc.state()
    }

    pub(crate) fn slpc_status(&self) -> Option<Status> {
        self.slpc.status()
    }

    pub(crate) fn slpc_frequency_range(
        &mut self,
        range: FrequencyRange,
        now: u64,
    ) -> Result<(), SchedulingError> {
        self.slpc
            .set_range(range, now)
            .map_err(SchedulingError::Slpc)
    }

    pub(crate) fn slpc_power_profile(
        &mut self,
        profile: PowerProfile,
        now: u64,
    ) -> Result<(), SchedulingError> {
        self.slpc
            .set_profile(profile, now)
            .map_err(SchedulingError::Slpc)
    }

    /// xe_guc_pc_start: zero the 8 KiB shared data, publish its size and
    /// request SLPC_EVENT_RESET. Completion is observed in `poll`.
    pub(crate) fn begin_slpc<M: MmioWindow>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        limits: Limits,
        now: u64,
    ) -> Result<(), SchedulingError> {
        if !self.published || self.lost || self.slpc.state() != SlpcState::Off {
            return Err(SchedulingError::State);
        }
        // Validate the absolute deadline before exposing any allocation.
        now.checked_add(1_005_000_000)
            .ok_or(SchedulingError::Timeout)?;
        let r = &mut *self.resources;
        let shared = r.allocator.alloc(2).map_err(SchedulingError::Allocation)?;
        let clashes = r
            .engines
            .iter()
            .flat_map(|e| [&e.hwsp, &e.golden])
            .chain(r.seed_image.iter())
            .chain(r.contexts.iter().flat_map(|c| [&c.image, &c.ring]))
            .any(|old| overlap(old, &shared));
        if !valid(&shared) || shared.size_pages() != 2 || clashes {
            r.allocator.free(shared);
            return Err(SchedulingError::Address);
        }
        if !shared.coherent_for_device() {
            r.allocator.free(shared);
            return Err(SchedulingError::Cache);
        }
        shared.zero_fill();
        shared.write32(0, 8192);
        if r.allocator.sync_for_device(&shared).is_err() {
            r.allocator.free(shared);
            return Err(SchedulingError::Cache);
        }
        let address = shared.ggtt_offset();
        // GuC never saw the address if the request is refused.
        if let Err(error) = ct.send(
            crate::intel_gpu_slpc::RESET_FENCE,
            0x3003,
            0,
            &[2, address, 0],
            true,
        ) {
            r.allocator.free(shared);
            return Err(SchedulingError::Transport(error));
        }
        r.slpc = Some(shared);
        self.slpc
            .start(limits, now)
            .map_err(SchedulingError::Slpc)?;
        Ok(())
    }

    fn progress_slpc<M: MmioWindow>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        now: u64,
    ) -> Result<(), SchedulingError> {
        let r = &mut *self.resources;
        if let Some(shared) = r.slpc.as_ref() {
            self.slpc
                .progress(ct, &mut r.allocator, shared, now)
                .map_err(SchedulingError::Transport)?;
        }
        Ok(())
    }

    /// No firmware context is registered, in flight or retiring.
    pub(crate) fn idle(&self) -> bool {
        self.defaults_ready() && self.resources.contexts.is_empty()
    }

    /// Continue the user epoch of a previous scheduler that stopped cleanly
    /// while idle: every user context then holds a complete saved image, so
    /// it is not a lost context. Refused once this scheduler ran user work.
    pub(crate) fn adopt_epoch(&mut self, epoch: u64) -> Result<(), SchedulingError> {
        if self.user_submitted || epoch == 0 {
            return Err(SchedulingError::State);
        }
        self.epoch = epoch;
        Ok(())
    }

    pub(crate) fn submit_user(
        &mut self,
        now: u64,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: Option<&crate::intel_gpu_user::UserOutput<'_>>,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        if self.user_epoch().is_none() || batch.0.platform() != Some(self.platform) {
            return Err(SchedulingError::State);
        }
        let engine = context.engine();
        let placements = context.placements();
        if context.parallel().map(|lanes| lanes.len() - 1) != batch.0.parallel().map(<[_]>::len) {
            return Err(SchedulingError::State);
        }
        if let Some(lanes) = context.parallel() {
            let first = self
                .engines
                .logical_instance(lanes[0])
                .ok_or(SchedulingError::State)?;
            if lanes.iter().enumerate().any(|(index, engine)| {
                first.checked_add(index as u16) != self.engines.logical_instance(*engine)
            }) {
                return Err(SchedulingError::State);
            }
        }
        if self.engines.logical_mask(placements).is_none()
            || placements.iter().any(|candidate| {
                candidate.lrc_pages(self.platform) != engine.lrc_pages(self.platform)
            })
        {
            return Err(SchedulingError::State);
        }
        let claim = context
            .claim(self.epoch, engine.lrc_pages(self.platform))
            .map_err(SchedulingError::Residency)?;
        self.user_submitted = true;
        self.submit_inner(now, engine, Some(batch.0), None, Some(claim), output)
    }

    pub(crate) fn can_prime(&self) -> bool {
        self.published
            && !self.lost
            && self.pristine
            && self.defaults == Defaults::Empty
            && self.resources.contexts.is_empty()
    }

    pub(crate) fn begin_defaults(
        &mut self,
        seed: ContextSeed,
        now: u64,
    ) -> Result<Arc<CompletionFence>, SchedulingError> {
        if !self.can_prime() {
            return Err(SchedulingError::Busy);
        }
        self.disable_wmtp = seed.disable_wmtp;
        let (id, _) = self.submit(now, Engine::Rcs0, None, Some(seed.commands()))?;
        let completion = Arc::new(CompletionFence::new());
        self.resources.defaults_completion = Some(completion.clone());
        self.defaults = Defaults::Seed(Engine::Rcs0, id);
        Ok(completion)
    }

    /// # Safety
    /// The batch and every nested command stream must be trusted kernel code.
    /// It must access only resident mappings, return with BB_END and leave
    /// global/transport/context/ring state and completion evidence untouched.
    /// No CPU, userspace mapping or peer may modify any leaf until the fence
    /// completes or full-engine reset is proven. This does not grant isolated
    /// user 3D execution; isolated user state and coordinated recovery remain gated.
    pub(crate) unsafe fn submit_resident(
        &mut self,
        now: u64,
        batch: ResidentBatch,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        // SAFETY: the unchanged trusted-batch contract is forwarded.
        unsafe { self.submit_resident_on(now, Engine::Rcs0, batch) }
    }

    /// # Safety
    /// Same trusted resident-batch contract as `submit_resident`.
    pub(crate) unsafe fn submit_resident_on(
        &mut self,
        now: u64,
        engine: Engine,
        batch: ResidentBatch,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        self.admit()?;
        if batch.platform() != Some(self.platform) || !self.engines.contains(engine) {
            return Err(SchedulingError::Address);
        }
        self.submit(now, engine, Some(batch), None)
    }

    fn submit(
        &mut self,
        now: u64,
        engine: Engine,
        resident: Option<ResidentBatch>,
        prefix: Option<Vec<u32>>,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        self.submit_inner(now, engine, resident, prefix, None, None)
    }

    /// Engines before the one being primed already publish golden state.
    fn golden_ready(&self, engine: Engine) -> bool {
        match self.defaults {
            Defaults::Ready => true,
            Defaults::Seed(next, _) | Defaults::Switch(next, _) | Defaults::Next(next) => {
                engine < next
            }
            Defaults::Empty => false,
        }
    }

    fn submit_inner(
        &mut self,
        now: u64,
        engine: Engine,
        resident: Option<ResidentBatch>,
        prefix: Option<Vec<u32>>,
        user: Option<crate::intel_gpu_user::ContextClaim>,
        output: Option<&crate::intel_gpu_user::UserOutput<'_>>,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        if !self.published || self.lost {
            return Err(SchedulingError::State);
        }
        if self.resources.contexts.len() == MAX_CONTEXTS {
            return Err(SchedulingError::Full);
        }
        let width = user
            .as_ref()
            .and_then(|claim| claim.parallel())
            .map_or(1, <[_]>::len);
        let placements = user.as_ref().map_or(EngineSet::of(&[engine]), |claim| {
            if width > 1 {
                EngineSet::of(&[engine])
            } else {
                claim.placements()
            }
        });
        let live = |stamp| self.resources.contexts.iter().any(|c| c.stamp == stamp);
        let (id, stamp) = if width == 1 {
            self.identities.candidate(live)?
        } else {
            self.identities.candidate_width(width as u16, live)?
        };
        let deadline = now.checked_add(TIMEOUT).ok_or(SchedulingError::Timeout)?;
        let golden_ready = self.golden_ready(engine);
        let r = &mut *self.resources;
        r.contexts
            .try_reserve(1)
            .map_err(|_| SchedulingError::Full)?;
        let pages = engine.lrc_pages(self.platform);
        let image = r
            .allocator
            .alloc(pages)
            .map_err(SchedulingError::Allocation)?;
        let ring = match r.allocator.alloc(2) {
            Ok(b) => b,
            Err(e) => {
                r.allocator.free(image);
                return Err(SchedulingError::Allocation(e));
            }
        };
        let invalid = !valid(&image)
            || !valid(&ring)
            || image.size_pages() != pages
            || ring.size_pages() != 2
            || !image.coherent_for_device()
            || !ring.coherent_for_device()
            || overlap(&image, &ring)
            || r.slpc
                .as_ref()
                .is_some_and(|old| overlap(old, &image) || overlap(old, &ring))
            || r.seed_image
                .as_ref()
                .is_some_and(|old| overlap(old, &image) || overlap(old, &ring))
            || r.engines
                .iter()
                .flat_map(|e| [&e.hwsp, &e.golden])
                .any(|old| overlap(old, &image) || overlap(old, &ring))
            || r.contexts
                .iter()
                .flat_map(Context::backings)
                .any(|old| overlap(old, &image) || overlap(old, &ring));
        if invalid {
            r.allocator.free(ring);
            r.allocator.free(image);
            return Err(SchedulingError::Address);
        }
        image.zero_fill();
        ring.zero_fill();
        if golden_ready {
            let golden = &state_of(&r.engines, engine).golden;
            for off in (REGS..u64::from(pages) * 4096).step_by(4) {
                image.write32(off, golden.read32(off));
            }
            if let Some(user) = &user {
                user.restore(&image);
            }
            image.write32(REGS + 3 * 4, 0x00090008);
            image.write32(REGS + 5 * 4, 0);
            image.write32(REGS + 9 * 4, ring.ggtt_offset());
            image.write32(REGS + 11 * 4, 0x1001);
            image.write32(REGS + 0x23 * 4, 0);
            for slot in (0x25..=0x33).step_by(2) {
                image.write32(REGS + slot * 4, 0);
            }
        } else if engine != Engine::Rcs0 {
            crate::intel_gpu_engine::xcs_image(engine, &image, self.platform, ring.ggtt_offset());
        } else {
            context_image(&image, self.platform, ring.ggtt_offset());
        }
        let mutating = resident.is_some() || prefix.is_some();
        let mut words: Vec<u32> = if let Some(prefix) = prefix {
            let mut words = alloc::vec![0x04000001];
            words.extend_from_slice(&prefix);
            if engine.is_copy() {
                crate::intel_gpu_engine::copy_completion(image.ggtt_offset(), stamp, &mut words);
            } else {
                render_completion(
                    self.platform,
                    engine.is_compute(),
                    image.ggtt_offset(),
                    stamp,
                    &mut words,
                );
            }
            words
        } else if let Some(batch) = &resident {
            let root = batch.space().root_descriptor();
            // xe_lrc.c::xe_lrc_set_ppgtt: PDP0 on DG2/MTL, PTBP on Xe2. The
            // slots are identical in the RCS and BCS register tables.
            image.write32(REGS + 0x31 * 4, (root >> 32) as u32);
            image.write32(REGS + 0x33 * 4, root as u32);
            if engine.is_copy() {
                crate::intel_gpu_engine::copy_ring(
                    (!batch.skip_batch()).then_some(batch.address()),
                    batch.user_fence(),
                    image.ggtt_offset(),
                    stamp,
                )
            } else {
                let mut words = resident_ring(
                    self.platform,
                    engine.is_compute(),
                    (!batch.skip_batch()).then_some(batch.address()),
                    image.ggtt_offset(),
                    stamp,
                );
                if let Some((address, value)) = batch.user_fence() {
                    // MIT xe_ring_ops.c::emit_store_imm_ppgtt_posted: qword
                    // PPGTT store after the render-cache flush, before the owned
                    // GGTT breadcrumb. ResidentBatch validated writable residency.
                    let before_breadcrumb = words
                        .windows(2)
                        .position(|v| v == [0x7a000004, 0x01104080])
                        .expect("owned completion stream");
                    words.splice(
                        before_breadcrumb..before_breadcrumb,
                        [
                            0x10200003,
                            address as u32,
                            (address >> 32) as u32,
                            value as u32,
                            (value >> 32) as u32,
                            0,
                        ],
                    );
                }
                words
            }
        } else {
            alloc::vec![
                0x04000001,
                0,
                0x10400002,
                image.ggtt_offset() + BREADCRUMB as u32,
                0,
                stamp,
                0x01000000,
                0,
            ]
        };
        if user.is_some() {
            if placements.iter().count() > 1 {
                job_timeout::setup_virtual(&image, self.platform);
            } else {
                job_timeout::setup(&image, self.platform);
            }
            job_timeout::prefix(image.ggtt_offset(), stamp, engine, &mut words);
        }
        if words.len() % 2 != 0 {
            words.push(0);
        }
        if words.len() > ring.size_pages() as usize * 1024 {
            r.allocator.free(ring);
            r.allocator.free(image);
            return Err(SchedulingError::Full);
        }
        let tail = words.len() as u32 * 4;
        for (i, word) in words.into_iter().enumerate() {
            ring.write32(i as u64 * 4, word);
        }
        image.write32(REGS + 7 * 4, tail);
        let parallel = if width > 1 {
            match parallel::prepare(
                r,
                parallel::Spec {
                    platform: self.platform,
                    parent: [&image, &ring],
                    parent_tail: tail,
                    id,
                    stamp,
                    resident: resident.as_ref().expect("parallel resident"),
                    user: user.as_ref().expect("parallel user"),
                },
            ) {
                Ok(group) => Some(group),
                Err(e) => {
                    r.allocator.free(ring);
                    r.allocator.free(image);
                    return Err(e);
                }
            }
        } else {
            None
        };
        let completion = Arc::new(CompletionFence::new());
        if let Some(batch) = &resident {
            if let Err(error) = batch.reserve(&completion) {
                if let Some(group) = parallel {
                    group.free(&mut r.allocator);
                }
                r.allocator.free(ring);
                r.allocator.free(image);
                return Err(SchedulingError::Residency(error));
            }
        }
        if r.allocator.sync_for_device(&image).is_err()
            || r.allocator.sync_for_device(&ring).is_err()
            || resident
                .as_ref()
                .is_some_and(|batch| !batch.publish_for_device())
        {
            if let Some(group) = parallel {
                group.free(&mut r.allocator);
            }
            r.allocator.free(ring);
            r.allocator.free(image);
            drop(resident);
            completion.signal(Err(JobError::Reset));
            return Err(SchedulingError::Cache);
        }
        if let Some(output) = output {
            if let Err(error) = output.install(completion.clone()) {
                if let Some(group) = parallel {
                    group.free(&mut r.allocator);
                }
                r.allocator.free(ring);
                r.allocator.free(image);
                drop(resident);
                completion.signal(Err(JobError::Reset));
                return Err(SchedulingError::Output(error));
            }
        }
        r.contexts.push(Context {
            user: user.map(|claim| claim.publish(completion.clone())),
            engine,
            placements,
            id,
            stamp,
            image,
            ring,
            phase: Phase::Invalidate,
            deadline,
            runtime: job_timeout::Runtime::default(),
            fence: completion.clone(),
            resident,
            tail,
            timed_out: false,
            reset: false,
            primary_finished: false,
            parallel,
        });
        if mutating {
            self.pristine = false;
        }
        for lane in 0..width {
            self.identities.claim(id + lane as u16, stamp);
        }
        Ok((id, completion))
    }

    pub(crate) fn poll<M: MmioWindow>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        now: u64,
    ) -> Result<(), SchedulingError> {
        if self.lost {
            return Err(SchedulingError::State);
        }
        let result = self.progress(ct, now);
        if result.is_err() {
            self.lost = true;
        }
        result
    }

    fn progress<M: MmioWindow>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        now: u64,
    ) -> Result<(), SchedulingError> {
        // Bound one poll even if firmware continuously emits events.
        for _ in 0..64 {
            let Some(message) = ct.receive().map_err(SchedulingError::Transport)? else {
                break;
            };
            self.event(message, now)?;
        }
        self.progress_slpc(ct, now)?;
        if let Defaults::Seed(engine, _) = self.defaults {
            if self.resources.seed_image.is_some() {
                let (id, _) = self.submit(now, engine, None, None)?;
                self.defaults = Defaults::Switch(engine, id);
            }
        } else if let Defaults::Next(engine) = self.defaults {
            // Linux records every class's default LRC; BCS's WA job is
            // emit_wa_job's BLIT_CCTL RMW and CCS's only the Xe2 WMTP level,
            // with no render 3D state.
            let seed = if engine.is_copy() {
                crate::intel_gpu_engine::copy_seed(engine, self.platform)
            } else {
                crate::intel_gpu_engine::compute_seed(engine, self.platform, self.disable_wmtp)
            };
            match self.submit(now, engine, None, Some(seed)) {
                Ok((id, _)) => self.defaults = Defaults::Seed(engine, id),
                Err(SchedulingError::Full) => {}
                Err(error) => return Err(error),
            }
        }
        let resources = &mut *self.resources;
        let diagnostic_total = resources.contexts.iter().map(Context::width).sum();
        for context in &mut resources.contexts {
            if context.phase == Phase::Running {
                resources
                    .allocator
                    .sync_for_cpu(&context.image)
                    .map_err(|_| SchedulingError::Cache)?;
                fence(Ordering::Acquire);
                let seq = context.image.read32(BREADCRUMB);
                if seq != 0 && seq != context.stamp {
                    return Err(SchedulingError::Protocol);
                }
                if seq != 0 && !context.primary_finished {
                    let physical = job_timeout::observed_engine(
                        &context.image,
                        context.stamp,
                        context.placements,
                    )?
                    .ok_or(SchedulingError::Protocol)?;
                    resources
                        .engines
                        .iter_mut()
                        .find(|e| e.engine == physical)
                        .expect("scheduler engine")
                        .last_progress = Some(now);
                    context.primary_finished = true;
                }
                if let Some(group) = &mut context.parallel {
                    resources
                        .allocator
                        .sync_for_cpu(&group.scratch)
                        .map_err(|_| SchedulingError::Cache)?;
                    if !group.valid_wq() {
                        return Err(SchedulingError::Protocol);
                    }
                    for lane in &mut group.children {
                        resources
                            .allocator
                            .sync_for_cpu(&lane.image)
                            .map_err(|_| SchedulingError::Cache)?;
                        fence(Ordering::Acquire);
                        let seq = lane.image.read32(BREADCRUMB);
                        if seq != 0 && seq != context.stamp {
                            return Err(SchedulingError::Protocol);
                        }
                        if seq != 0 && !lane.finished {
                            resources
                                .engines
                                .iter_mut()
                                .find(|e| e.engine == lane.engine)
                                .expect("scheduler engine")
                                .last_progress = Some(now);
                            lane.finished = true;
                        }
                    }
                }
                if context.primary_finished
                    && context
                        .parallel
                        .as_ref()
                        .is_none_or(|g| g.children.iter().all(|lane| lane.finished))
                {
                    context.phase = Phase::Disable;
                    // Each LRC must finish. A parent breadcrumb never retires
                    // an outstanding child, its WQ, or shared PPGTT graph.
                    context.deadline = now.checked_add(TIMEOUT).ok_or(SchedulingError::Timeout)?;
                }
            }
            if now >= context.deadline {
                // Protocol transitions, kernel work and a second expiry
                // remain bounded by wall clock and require a full GT reset.
                if context.user.is_none()
                    || context.timed_out
                    || context.reset
                    || context.phase != Phase::Running
                {
                    return Err(SchedulingError::Timeout);
                }
                let (mut expired, progressed) = if context.primary_finished {
                    (false, false)
                } else if context.placements.iter().count() > 1 {
                    context.runtime.expired_on(
                        &context.image,
                        context.stamp,
                        context.placements,
                        ct.window(),
                    )?
                } else {
                    context.runtime.expired(
                        &context.image,
                        context.stamp,
                        context.engine,
                        ct.window(),
                    )?
                };
                if progressed {
                    let physical = job_timeout::observed_engine(
                        &context.image,
                        context.stamp,
                        context.placements,
                    )?
                    .ok_or(SchedulingError::Protocol)?;
                    resources
                        .engines
                        .iter_mut()
                        .find(|e| e.engine == physical)
                        .expect("scheduler engine")
                        .last_progress = Some(now);
                }
                if let Some(group) = &mut context.parallel {
                    if expired {
                        group.timeout_lanes |= 1;
                    }
                    for (index, lane) in group.children.iter_mut().enumerate() {
                        if lane.finished {
                            continue;
                        }
                        let (child_expired, child_progressed) = lane.runtime.expired(
                            &lane.image,
                            context.stamp,
                            lane.engine,
                            ct.window(),
                        )?;
                        if child_progressed {
                            resources
                                .engines
                                .iter_mut()
                                .find(|e| e.engine == lane.engine)
                                .expect("scheduler engine")
                                .last_progress = Some(now);
                        }
                        if child_expired {
                            group.timeout_lanes |= 1 << (index + 1);
                            expired = true;
                        }
                    }
                }
                context.deadline = now.checked_add(TIMEOUT).ok_or(SchedulingError::Timeout)?;
                if expired {
                    // GuC preempts this context alone or resets its engine
                    // if it cannot preempt within the firmware policy bound.
                    context.timed_out = true;
                    if self.pending_error.is_none() {
                        let mut contexts = Contexts::new(diagnostic_total);
                        contexts.push(context.diagnostic());
                        for child in context.child_diagnostics() {
                            contexts.push(child);
                        }
                        self.pending_error = Some(Report::capture(
                            Capture {
                                platform: self.platform,
                                reason: Reason::Timeout,
                                epoch: self.epoch,
                                now_ns: now,
                                state: crate::intel_gpu_guc_gt::GtState::SchedulingReady,
                                engines: self.engines,
                            },
                            contexts,
                            |offset| {
                                // GuCGt checked awake before this poll; its PCI
                                // owner retains D0/reset ownership throughout. The
                                // authorized window rechecks current cap per read.
                                let mmio = ct.window();
                                let request = mmio.read32(0xa188);
                                let render = mmio.read32(0xd84);
                                let ack = mmio.read32(self.platform.guc_forcewake_ack()?);
                                if request == u32::MAX
                                    || render == u32::MAX
                                    || ack == u32::MAX
                                    || request & 1 == 0
                                    || render & 1 == 0
                                    || ack & 1 == 0
                                {
                                    return None;
                                }
                                let value = mmio.read32(offset);
                                (value != u32::MAX).then_some(value)
                            },
                        ));
                    }
                    context.phase = Phase::Disable;
                }
            }
            let id = u32::from(context.id);
            let (action, payload, next): (u16, Vec<u32>, Phase) = match context.phase {
                Phase::Invalidate => (
                    0x7000,
                    alloc::vec![context.stamp, 0x80000003],
                    Phase::Invalidating,
                ),
                Phase::RetireInvalidate => (
                    0x7000,
                    alloc::vec![context.stamp | 0x80000000, 0x80000003],
                    Phase::RetireInvalidating,
                ),
                Phase::Register => {
                    let descriptor = context.image.ggtt_offset()
                        | if context.resident.is_some() {
                            0x119
                        } else {
                            0x19
                        };
                    let mask = self
                        .engines
                        .logical_mask(context.placements)
                        .expect("published placements");
                    if let Some(group) = &context.parallel {
                        let scratch = group.scratch.ggtt_offset();
                        let mut payload = alloc::vec![
                            1,
                            id,
                            context.engine.guc_class(),
                            mask,
                            scratch,
                            0,
                            scratch + 1024,
                            0,
                            1024,
                            group.width() as u32,
                            descriptor,
                            0,
                        ];
                        for lane in &group.children {
                            payload.extend_from_slice(&[lane.image.ggtt_offset() | 0x119, 0]);
                        }
                        (0x4601, payload, Phase::Policy)
                    } else {
                        (
                            0x4502,
                            alloc::vec![
                                1,
                                id,
                                context.engine.guc_class(),
                                mask,
                                0,
                                0,
                                0,
                                0,
                                0,
                                descriptor,
                                0,
                            ],
                            Phase::Policy,
                        )
                    }
                }
                Phase::Policy => (
                    0x100b,
                    {
                        let (priority, timeslice) = context
                            .user
                            .as_ref()
                            .map_or((3, 1000), |user| user.policy());
                        alloc::vec![
                            id, 0x20030001, priority, 0x20010001, timeslice, 0x20020001, 500000
                        ]
                    },
                    Phase::Enable,
                ),
                Phase::Enable => (0x1001, alloc::vec![id, 1], Phase::Enabling),
                // Parallel queues need the additional SCHED_CONTEXT after
                // ENABLE; only ENABLE produces a scheduling-mode reply.
                Phase::Dispatch => (0x1000, alloc::vec![id], Phase::Running),
                Phase::Disable => (0x1001, alloc::vec![id, 0], Phase::Disabling),
                Phase::Deregister => (0x4503, alloc::vec![id], Phase::Deregistering),
                _ => continue,
            };
            match ct.send(context.id, action, 0, &payload, true) {
                Ok(()) => {
                    context.phase = next;
                    if next == Phase::Running {
                        context.fence.mark_submitted();
                        context.deadline =
                            now.checked_add(TIMEOUT).ok_or(SchedulingError::Timeout)?;
                        if context.user.is_some() {
                            for engine in &mut resources.engines {
                                if context.owns_engine(engine.engine) {
                                    engine.last_progress.get_or_insert(now);
                                }
                            }
                        }
                    }
                }
                Err(TransportError::Ct(crate::intel_gpu_guc::GuCError::Full)) => {}
                Err(error) => return Err(SchedulingError::Transport(error)),
            }
        }
        for context in resources
            .contexts
            .iter()
            .filter(|context| context.user.is_some() && context.phase == Phase::Running)
        {
            // A queued virtual context or gang may wait for an allowed
            // engine executing other work. Only a lack of GPU progress on
            // every unfinished lane/placement justifies the global fallback.
            // Finished lanes cannot mask the remaining lane's stall. Active
            // per-lane runtime budgets above remain independent.
            let newest = context
                .placements
                .iter()
                .filter(|_| !context.primary_finished)
                .chain(
                    context
                        .parallel
                        .iter()
                        .flat_map(|g| g.children.iter())
                        .filter(|lane| !lane.finished)
                        .map(|lane| lane.engine),
                )
                .filter_map(|engine| state_of(&resources.engines, engine).last_progress)
                .max();
            if newest.is_some_and(|last| now.saturating_sub(last) >= 3 * TIMEOUT) {
                return Err(SchedulingError::Timeout);
            }
        }
        for engine in &mut resources.engines {
            if !resources.contexts.iter().any(|context| {
                context.owns_engine(engine.engine)
                    && context.user.is_some()
                    && context.phase == Phase::Running
            }) {
                engine.last_progress = None;
            }
        }
        Ok(())
    }

    fn event(&mut self, message: GuCMessage, now: u64) -> Result<(), SchedulingError> {
        // SLPC uses a disjoint fence namespace and fails independently.
        if self.slpc.event(&message) {
            return Ok(());
        }
        if message.kind != 1 || message.auxiliary >> 16 != 0 {
            return Err(SchedulingError::Protocol);
        }
        let action = message.auxiliary as u16;
        // ENGINE_FAILURE_NOTIFICATION (0x1009, GuC could not reset an engine)
        // stays a protocol loss: Linux answers it with a GT reset.
        if !matches!(action, 0x1002 | 0x1008 | 0x4600 | 0x7001) {
            return Err(SchedulingError::Protocol);
        }
        let len = if action == 0x1002 { 2 } else { 1 };
        // CONTEXT_RESET_NOTIFICATION carries the GuC context ID alone.
        if message.payload.len() != len {
            return Err(SchedulingError::Protocol);
        }
        let cookie = message.payload[0];
        let index = self
            .resources
            .contexts
            .iter()
            .position(|c| {
                if action == 0x7001 {
                    c.stamp == cookie & 0x7fffffff
                } else {
                    cookie >= u32::from(c.id) && cookie < u32::from(c.id) + c.width() as u32
                }
            })
            .ok_or(SchedulingError::Protocol)?;
        let resources = &mut *self.resources;
        let diagnostic_total = resources.contexts.iter().map(Context::width).sum();
        let c = &mut resources.contexts[index];
        if action == 0x4600 || (action == 0x7001 && c.phase == Phase::RetireInvalidating) {
            for backing in c.backings() {
                resources
                    .allocator
                    .sync_for_cpu(backing)
                    .map_err(|_| SchedulingError::Cache)?;
            }
            fence(Ordering::Acquire);
        }
        match (action, c.phase, message.payload.get(1).copied()) {
            (0x7001, Phase::Invalidating, None) if cookie == c.stamp => c.phase = Phase::Register,
            (0x7001, Phase::RetireInvalidating, None) if cookie == (c.stamp | 0x80000000) => {
                fence(Ordering::Acquire);
                let hung = c.timed_out || c.reset;
                if !hung
                    && (!c.all_finished() || c.parallel.as_ref().is_some_and(|g| !g.valid_wq()))
                {
                    return Err(SchedulingError::Protocol);
                }
                // A hung job's saved state is never captured: its context
                // is banned below.
                if let Some(user) = c.user.as_ref().filter(|_| !hung) {
                    resources
                        .allocator
                        .sync_for_cpu(&c.image)
                        .map_err(|_| SchedulingError::Cache)?;
                    job_timeout::observed_engine(&c.image, c.stamp, c.placements)?
                        .ok_or(SchedulingError::Protocol)?;
                    if let Some(group) = &c.parallel {
                        user.capture_lanes(
                            core::iter::once(&c.image)
                                .chain(group.children.iter().map(|lane| &lane.image)),
                            c.engine.first_lri(self.platform),
                        )
                        .map_err(SchedulingError::Residency)?;
                    } else {
                        user.capture(&c.image, c.engine.first_lri(self.platform))
                            .map_err(SchedulingError::Residency)?;
                    }
                }
                let c = resources.contexts.remove(index);
                let width = c.width();
                let r = resources;
                r.allocator.free(c.ring);
                if let Some(group) = c.parallel {
                    group.free(&mut r.allocator);
                    for lane in 1..width {
                        self.identities.retire(c.id + lane as u16);
                    }
                }
                if self.defaults == Defaults::Seed(c.engine, c.id) {
                    r.seed_image = Some(c.image);
                    r.seed_id = Some(c.id);
                } else {
                    r.allocator.free(c.image);
                    self.identities.retire(c.id);
                }
                // Drop all PPGTT tables and BO references before terminal
                // publication. Deregistration and the final TLB ACK are proven,
                // so even a reset or preempted job no longer reaches them.
                drop(c.resident);
                if let Some(user) = c.user {
                    if hung {
                        user.finish_hung();
                    } else {
                        user.finish(false);
                    }
                }
                c.fence
                    .signal(if hung { Err(JobError::Hang) } else { Ok(()) });
                if self.defaults == Defaults::Switch(c.engine, c.id) {
                    self.capture_defaults(c.engine)?;
                }
            }
            (0x1002, Phase::Enabling, Some(1)) => {
                c.phase = if c.parallel.is_some() {
                    Phase::Dispatch
                } else {
                    Phase::Running
                };
                if c.parallel.is_none() {
                    c.fence.mark_submitted();
                }
                // Start the watchdog when GuC may run it. User execution
                // time itself comes from the ring marker/LRC timestamps.
                c.deadline = now.checked_add(TIMEOUT).ok_or(SchedulingError::Timeout)?;
                if c.user.is_some() {
                    for engine in resources
                        .engines
                        .iter_mut()
                        .filter(|engine| c.owns_engine(engine.engine))
                    {
                        engine.last_progress.get_or_insert(now);
                    }
                }
            }
            (0x1002, Phase::Disabling, Some(0)) => c.phase = Phase::Deregister,
            (
                0x1008,
                Phase::Running
                | Phase::Dispatch
                | Phase::Disable
                | Phase::Disabling
                | Phase::Deregister
                | Phase::Deregistering,
                None,
            ) => {
                // GuC reset the engine under this context. A kernel job must
                // never hang; a user job is taken off and its context banned.
                if c.user.is_none() {
                    return Err(SchedulingError::Timeout);
                }
                if !c.timed_out && !c.reset {
                    c.deadline = now.checked_add(TIMEOUT).ok_or(SchedulingError::Timeout)?;
                }
                c.reset = true;
                if let Some(group) = &mut c.parallel {
                    group.reset_lanes |= 1 << (cookie - u32::from(c.id));
                }
                if !c.timed_out && self.pending_error.is_none() {
                    let mut contexts = Contexts::new(diagnostic_total);
                    contexts.push(c.diagnostic());
                    for child in c.child_diagnostics() {
                        contexts.push(child);
                    }
                    // GuC's notification follows its engine reset. Preserve
                    // software facts, without claiming a pre-reset MMIO image.
                    self.pending_error = Some(Report::capture(
                        Capture {
                            platform: self.platform,
                            reason: Reason::EngineReset,
                            epoch: self.epoch,
                            now_ns: now,
                            state: crate::intel_gpu_guc_gt::GtState::SchedulingReady,
                            engines: self.engines,
                        },
                        contexts,
                        |_| None,
                    ));
                }
                if matches!(c.phase, Phase::Running | Phase::Dispatch) {
                    c.phase = Phase::Disable;
                }
            }
            (0x4600, Phase::Deregistering, None) => {
                fence(Ordering::Acquire);
                let finished = c.all_finished() && c.parallel.as_ref().is_none_or(|g| g.valid_wq());
                if !finished && !c.timed_out && !c.reset {
                    return Err(SchedulingError::Protocol);
                }
                // A job that completed while it was being disabled was slow,
                // not hung: it retires normally unless GuC reset it.
                if finished && !c.reset {
                    c.timed_out = false;
                }
                c.phase = Phase::RetireInvalidate;
            }
            _ => return Err(SchedulingError::Protocol),
        }
        Ok(())
    }

    fn capture_defaults(&mut self, engine: Engine) -> Result<(), SchedulingError> {
        let r = &mut *self.resources;
        let image = r.seed_image.as_ref().ok_or(SchedulingError::State)?;
        r.allocator
            .sync_for_cpu(image)
            .map_err(|_| SchedulingError::Cache)?;
        // The seed was fully retired, then a different context executed and
        // retired. The image cannot still be resident in the engine.
        if image.read32(REGS + 4) != engine.first_lri(self.platform)
            || image.size_pages() != engine.lrc_pages(self.platform)
            || image.read32(REGS + 0x33 * 4) != 0
            || image.read32(REGS + 0x31 * 4) != 0
        {
            return Err(SchedulingError::Protocol);
        }
        let golden = &state_of(&r.engines, engine).golden;
        golden.zero_fill();
        for off in (REGS..u64::from(image.size_pages()) * 4096).step_by(4) {
            golden.write32(off, image.read32(off));
        }
        golden.write32(REGS + 3 * 4, 0x00090008);
        for slot in [5, 7, 9, 0x23] {
            golden.write32(REGS + slot * 4, 0);
        }
        r.allocator
            .sync_for_device(golden)
            .map_err(|_| SchedulingError::Cache)?;
        let next = self.engines.iter().find(|e| *e > engine);
        self.defaults = next.map_or(Defaults::Ready, Defaults::Next);
        self.identities
            .retire(r.seed_id.take().expect("retired seed identity"));
        r.allocator
            .free(r.seed_image.take().expect("owned retired seed"));
        if next.is_none() {
            r.defaults_completion
                .as_ref()
                .expect("owned priming fence")
                .signal(Ok(()));
        }
        Ok(())
    }

    /// # Safety
    /// GuC is in reset with firmware DMA idle AND GRDOM_FULL has completed.
    /// No other host owner can re-arm the retired HWS/LRC/GGTT addresses.
    pub(crate) unsafe fn release_after_reset(mut self) {
        self.published = false;
        self.free();
    }

    fn free(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        // SAFETY: called once by Drop before publication, or proven reset.
        let mut r = unsafe { ManuallyDrop::take(&mut self.resources) };
        for c in r.contexts.drain(..) {
            r.allocator.free(c.ring);
            r.allocator.free(c.image);
            if let Some(group) = c.parallel {
                group.free(&mut r.allocator);
            }
            drop(c.resident);
            if let Some(user) = c.user {
                user.finish(true);
            }
            c.fence.signal(Err(JobError::Reset));
        }
        if let Some(image) = r.seed_image.take() {
            r.allocator.free(image);
        }
        if let Some(shared) = r.slpc.take() {
            r.allocator.free(shared);
        }
        for engine in r.engines.drain(..).rev() {
            r.allocator.free(engine.golden);
            r.allocator.free(engine.hwsp);
        }
        if let Some(completion) = r.defaults_completion {
            completion.signal(Err(JobError::Reset));
        }
    }
}

impl<A: BootAllocator> Drop for GuCScheduler<A> {
    fn drop(&mut self) {
        if !self.published {
            self.free();
        }
    }
}

fn valid(b: &impl GpuBacking) -> bool {
    b.ggtt_offset() >= 0x800000
        && b.ggtt_offset() % 4096 == 0
        && b.size_pages() != 0
        && (b.ggtt_offset() as u64 + b.size_pages() as u64 * 4096) <= 0xfee00000
}
fn overlap(a: &impl GpuBacking, b: &impl GpuBacking) -> bool {
    (a.ggtt_offset() as u64) < b.ggtt_offset() as u64 + b.size_pages() as u64 * 4096
        && (b.ggtt_offset() as u64) < a.ggtt_offset() as u64 + a.size_pages() as u64 * 4096
}

/// Single nonsecure PPGTT render job, following xe_ring_ops.c. Preparser/TLB
/// invalidation precedes the PPGTT batch; HDC/render/depth/data cache drain
/// precedes the separate GGTT post-sync completion write. MTL needs AuxCCS
/// invalidation; DG2 and Xe-LPG need the extra
/// depth flush (Wa_14016712196). All tails are qword aligned.
/// Compute queues (xe_ring_ops.c mask_flags = PIPE_CONTROL_3D_ENGINE_FLAGS)
/// drop VF invalidation (and its L3 read-only invalidate) and the tile,
/// render-target and depth flushes; Wa_14016712196's depth flush remains.
fn resident_ring(
    platform: GtPlatform,
    compute: bool,
    batch: Option<u64>,
    image: u32,
    seq: u32,
) -> Vec<u32> {
    let (header, flags) = if compute {
        (0x7a000004, 0x20344c0c)
    } else {
        (0x7a000404, 0x20344c1c)
    };
    let mut words = alloc::vec![0x04000001, 0x02800101, header, flags, 0xd0, 0, 0, 0,];
    if matches!(platform, GtPlatform::Integrated(_)) {
        words.extend_from_slice(&[0x11020001, 0x4208, 1, 0]);
    }
    if let Some(batch) = batch {
        words.extend_from_slice(&[
            0x02800100,
            0x18800101,
            batch as u32,
            (batch >> 32) as u32,
            0x04000000,
        ]);
    }
    render_completion(platform, compute, image, seq, &mut words);
    words
}

fn render_completion(
    platform: GtPlatform,
    compute: bool,
    image: u32,
    seq: u32,
    words: &mut Vec<u32>,
) {
    if platform != GtPlatform::Battlemage {
        words.extend_from_slice(&[0x7a000004, 1, 0xd0, 0, 0, 0]);
    }
    words.extend_from_slice(&[
        0x7a000204,
        if compute { 0x001000a0 } else { 0x101010a1 },
        0,
        0,
        0,
        0,
        0x7a000004,
        0x01104080,
        image + BREADCRUMB as u32,
        0,
        seq,
        0,
        0x01000000,
        0x04000001,
        0x02800000,
    ]);
    if words.len() % 2 != 0 {
        words.push(0);
    }
}

fn context_image(image: &impl GpuBacking, platform: GtPlatform, ring: u32) {
    // Literal register groups from xe_lrc.c's DG2/MTL/Xe2 RCS tables;
    // lengths and command placement differ from the Gen12 execlists codec.
    let groups: &[&[u32]] = &[
        &[
            0x244, 0x034, 0x030, 0x038, 0x03c, 0x168, 0x140, 0x110, 0x1c0, 0x1c4, 0x1c8, 0x180,
            0x2b4, 0x120, 0x124,
        ],
        if platform == GtPlatform::Battlemage {
            &[
                0x3a8, 0x3ac, 0x108, 0x284, 0x280, 0x27c, 0x278, 0x274, 0x270,
            ]
        } else {
            &[
                0x3a8, 0x28c, 0x288, 0x284, 0x280, 0x27c, 0x278, 0x274, 0x270,
            ]
        },
    ];
    let mut cursor = 0u64;
    for group in groups {
        cursor += 1;
        image.write32(REGS + cursor * 4, 0x11081000 | (group.len() as u32 * 2 - 1));
        cursor += 1;
        for offset in *group {
            image.write32(REGS + cursor * 4, 0x2000 + offset);
            cursor += 2;
        }
    }
    let extra: &[u32] = if platform == GtPlatform::Alchemist {
        &[0x1b0, 0x5a8, 0x5ac]
    } else {
        cursor += 2;
        &[0x5a8, 0x5ac]
    };
    image.write32(REGS + cursor * 4, 0x11081000 | (extra.len() as u32 * 2 - 1));
    cursor += 1;
    for offset in extra {
        image.write32(REGS + cursor * 4, 0x2000 + offset);
        cursor += 2;
    }
    cursor += 6;
    image.write32(REGS + cursor * 4, 0x11080001);
    image.write32(REGS + (cursor + 1) * 4, 0x20c8);
    image.write32(REGS + (cursor + 3) * 4, 0x05000001);
    image.write32(REGS + 3 * 4, 0x00090009); // inhibit restore and synchronous switch
    image.write32(REGS + 9 * 4, ring);
    image.write32(REGS + 11 * 4, 0x1001); // 8 KiB ring
                                          // reset_stop_ring() sets the masked STOP_RING disable in value slot
                                          // 0x71 of the later register block; the initial inhibited restore skips it.
    image.write32(REGS + 0x71 * 4, 0x01000000);
}

#[cfg(feature = "kernel-test")]
mod identity_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_parallel_identity_contiguous_blocks_fragmentation_and_reuse() -> TestResult {
        let mut ids = Identities::new();
        assert_eq!(ids.candidate_width(2, |_| false), Ok((1, 1)));
        assert_eq!(ids.candidate_width(2, |_| false), Ok((1, 1)));
        for expected in (1..64).step_by(2) {
            let (id, stamp) = ids.candidate_width(2, |_| false).unwrap();
            assert_eq!(id, expected);
            ids.claim(id, stamp);
            ids.claim(id + 1, stamp);
        }
        assert_eq!(ids.used, u64::MAX);
        assert_eq!(
            ids.candidate_width(2, |_| false),
            Err(SchedulingError::Full)
        );
        // Releasing only the parent never creates a reusable two-ID block.
        for id in (1..64).step_by(2) {
            ids.retire(id);
        }
        assert_eq!(
            ids.candidate_width(2, |_| false),
            Err(SchedulingError::Full)
        );
        // The last/first slots are not contiguous in firmware ID space.
        ids.retire(64);
        ids.claim(63, 40);
        assert_eq!(
            ids.candidate_width(2, |_| false),
            Err(SchedulingError::Full)
        );
        ids.retire(8);
        assert_eq!(ids.candidate_width(2, |_| false), Ok((7, 41)));
        let (id, stamp) = ids.candidate_width(2, |_| false).unwrap();
        ids.claim(id, stamp);
        ids.claim(id + 1, stamp);
        assert_eq!(
            ids.candidate_width(2, |_| false),
            Err(SchedulingError::Full)
        );
        ids.retire(7);
        ids.retire(8);
        ids.next_stamp = 0x7fffffff;
        assert_eq!(
            ids.candidate_width(2, |s| s == 0x7fffffff || s == 1),
            Ok((7, 2))
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_parallel",
        smoke_parallel_identity_contiguous_blocks_fragmentation_and_reuse
    );

    fn smoke_parallel_wide_identity_contiguous_leases_and_fragmentation() -> TestResult {
        for width in [3u16, 4] {
            let mut ids = Identities::new();
            let groups = 64 / width;
            for group in 0..groups {
                let expected = group * width + 1;
                let (id, stamp) = ids.candidate_width(width, |_| false).unwrap();
                assert_eq!(id, expected);
                for lane in 0..width {
                    ids.claim(id + lane, stamp);
                }
            }
            assert_eq!(
                ids.candidate_width(width, |_| false),
                Err(SchedulingError::Full)
            );
            // Partial lane release is not a reusable group, even with a
            // trailing free slot at the end of firmware ID space.
            for lane in 0..width - 1 {
                ids.retire(1 + lane);
            }
            assert_eq!(
                ids.candidate_width(width, |_| false),
                Err(SchedulingError::Full)
            );
            ids.retire(width);
            ids.next_stamp = 0x7fffffff;
            assert_eq!(
                ids.candidate_width(width, |stamp| stamp == 0x7fffffff || stamp == 1),
                Ok((1, 2))
            );
            let (id, stamp) = ids.candidate_width(width, |_| false).unwrap();
            for lane in 0..width {
                ids.claim(id + lane, stamp);
            }
            assert_eq!(
                ids.candidate_width(width, |_| false),
                Err(SchedulingError::Full)
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_parallel",
        smoke_parallel_wide_identity_contiguous_leases_and_fragmentation
    );

    fn smoke_identity_pool_full_wrap_and_failed_preview() -> TestResult {
        let mut ids = Identities::new();
        assert_eq!(ids.candidate(|_| false), Ok((1, 1)));
        assert_eq!(
            ids.candidate(|_| false),
            Ok((1, 1)),
            "a failed preparation must not consume an identity"
        );
        for expected in 1..=64 {
            let (id, stamp) = ids.candidate(|_| false).unwrap();
            assert_eq!(id, expected);
            ids.claim(id, stamp);
        }
        assert_eq!(ids.candidate(|_| false), Err(SchedulingError::Full));
        ids.retire(7);
        ids.next_stamp = 0x7fffffff;
        assert_eq!(
            ids.candidate(|s| s == 0x7fffffff || s == 1 || s == 2),
            Ok((7, 3))
        );
        ids.claim(7, 0x7fffffff);
        assert_eq!(ids.next_stamp, 1);
        assert_eq!(ids.candidate(|_| false), Err(SchedulingError::Full));
        ids.retire(7);
        assert_eq!(ids.candidate(|s| s == 1), Ok((7, 2)));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_gt",
        smoke_identity_pool_full_wrap_and_failed_preview
    );
}
