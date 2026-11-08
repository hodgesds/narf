//! Per-open nonsecure RCS contexts and the live userspace submission contract.
//!
//! Linux MIT b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_lrc.c,
//! xe_ring_ops.c and i915 gen8_engine_cs.c. BB_START bit 8 selects the
//! nonsecure PPGTT batch; LRC descriptor bit 8 independently selects PPGTT.
//! Rings, saved images and translation tables never enter a user mapping.

use crate::{
    intel_gpu_exec::ResidentBatch, intel_gpu_fence::CompletionFence, intel_gpu_gt::GtPlatform,
    intel_gpu_rcs::GpuBacking,
};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::{future::Future, pin::Pin};
use narf_filesystem::{FsError, FsFuture, InstallFdError, IoctlContext};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
static STATE_BYTES: AtomicUsize = AtomicUsize::new(0);
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_PARALLEL_WIDTH: usize = 4;

pub(crate) fn next_epoch() -> u64 {
    NEXT_EPOCH
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .expect("Intel GT epoch exhausted")
}

pub(crate) fn io_error() -> FsError {
    FsError::Io(narf_block::BlockError::IOError)
}

/// intel_guc_fwif.h GUC_CLIENT_PRIORITY_*: a lower value is a higher
/// priority. Userspace reaches HIGH..=NORMAL only.
pub(crate) const GUC_PRIORITY_KMD_HIGH: u32 = 0;
pub(crate) const GUC_PRIORITY_HIGH: u32 = 1;
pub(crate) const GUC_PRIORITY_KMD_NORMAL: u32 = 2;
pub(crate) const GUC_PRIORITY_NORMAL: u32 = 3;
/// i915_priolist_types.h: I915_PRIORITY_NORMAL is
/// I915_CONTEXT_DEFAULT_PRIORITY (0); I915_PRIORITY_DISPLAY follows
/// I915_PRIORITY_MAX (1024) and I915_PRIORITY_HEARTBEAT (1025).
const I915_PRIORITY_NORMAL: i32 = 0;
const I915_PRIORITY_DISPLAY: i32 = 1026;

/// intel_guc_submission.c::map_i915_prio_to_guc_prio. guc_context_init
/// applies it to ctx->sched.priority, so a default context is KMD_NORMAL.
pub(crate) const fn map_i915_prio_to_guc_prio(priority: i32) -> u32 {
    if priority == I915_PRIORITY_NORMAL {
        GUC_PRIORITY_KMD_NORMAL
    } else if priority < I915_PRIORITY_NORMAL {
        GUC_PRIORITY_NORMAL
    } else if priority < I915_PRIORITY_DISPLAY {
        GUC_PRIORITY_HIGH
    } else {
        GUC_PRIORITY_KMD_HIGH
    }
}

/// A backend advertises only a live, primed and execution-tested RCS0 owner.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UserStatus {
    pub epoch: u64,
    pub platform: GtPlatform,
    pub submission_version: (u8, u8, u8),
    /// Engines userspace may name: RCS0/BCS0, BMG BCS8 and fused CCS0.
    pub engines: crate::intel_gpu_engine::EngineSet,
}

/// The MTL/Arrow standalone media GT as native Xe gt_id 1 (type MEDIA).
/// Published only with `narf.intel.media_gt=1`, after every engine executed
/// and retired a private PPGTT job on the media GuC, and only while GT0 is
/// live. Its engines are VCS/VECS with dense logical instances on GT1.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MediaGtStatus {
    /// GT1's own scheduler epoch; contexts on its engines carry it.
    pub epoch: u64,
    pub engines: crate::intel_gpu_engine::EngineSet,
    /// Raw media GMD_ID (query_gt_list ip_ver_major/minor/rev).
    pub gmd: u32,
    /// GT1's command-streamer timestamp clock (xe_gt_clock_init on GT1).
    pub reference_clock: u32,
    /// GT1's own topology fuses (query_gt_topology for gt_id 1).
    pub topology: crate::intel_gpu_gt::media::MediaTopology,
}

/// Observed PF/graphics-GT facts for the native Xe discovery ABI. Published
/// before live admission; a PCI ID alone cannot supply the clock or GMD step.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceFacts {
    pub revision: u8,
    pub graphics_version: u16,
    pub graphics_step: u8,
    pub reference_clock: u32,
    /// i915_perf_oa_timestamp_frequency: the reference clock with
    /// Wa_18013179988's RPM_CONFIG0 CTC shift on 12.55 and 12.70..12.74,
    /// sampled with the clock and independent of the OA opt-in.
    pub oa_timestamp_frequency: u32,
}

/// Trusted metadata-only smallbar publication transaction. Faultable output
/// has already completed without any owner/namespace/GEM lock. The callback
/// calls `current` immediately before identity-safe VM/handle commit. The owner
/// retains PM/reset exclusion across the metadata call; no user callback,
/// Vm.state acquisition, await or executor bridge is permitted here.
pub type VramPublish<'a> =
    Box<dyn FnOnce(&mut dyn FnMut() -> Result<(), FsError>) -> Result<(), FsError> + Send + 'a>;

pub trait UserBackend: core::fmt::Debug + Send + Sync {
    fn status(&self) -> Option<UserStatus>;
    /// The published standalone media GT (native Xe gt_id 1). Default: none,
    /// as on every backend without `narf.intel.media_gt=1`.
    fn media_gt(&self) -> Option<MediaGtStatus> {
        None
    }
    /// Confirmed SLPC status (limits, range, profile) for the standalone media GT (GT1).
    fn media_gt_slpc_status(&self) -> Option<crate::intel_gpu_slpc::Status> {
        None
    }
    /// Accumulated MC6 residency in milliseconds for the standalone media GT (GT1).
    fn media_gt_rc6_residency_ms(&self) -> Option<u64> {
        None
    }
    /// Actual measured CAGF operating frequency in MHz for the standalone media GT (GT1).
    fn media_gt_act_freq_mhz(&self) -> Option<u32> {
        None
    }
    /// Confirmed SLPC status (limits, range, profile) for the main graphics GT (GT0).
    fn main_gt_slpc_status(&self) -> Option<crate::intel_gpu_slpc::Status> {
        None
    }
    /// Accumulated RC6 residency in milliseconds for the main graphics GT (GT0).
    fn main_gt_rc6_residency_ms(&self) -> Option<u64> {
        None
    }
    /// Actual measured CAGF operating frequency in MHz for the main graphics GT (GT0).
    fn main_gt_act_freq_mhz(&self) -> Option<u32> {
        None
    }
    /// Cached physical automatic global-reset availability for this live user
    /// epoch. Default refusal; discovery alone is not a recovery owner. No I/O.
    fn reset_availability_epoch(&self) -> Option<u64> {
        None
    }
    /// Actual HuC release under the retained reset/D0/wake/auth owner. This
    /// passive query cannot start or authenticate firmware; default refusal.
    fn huc_version(&self) -> FsFuture<'_, (u8, u8, u8)> {
        Box::pin(async { Err(FsError::NoDevice) })
    }
    /// A runtime-PM reference for a kernel CPU access to this card's LMEM
    /// BAR (Linux i915/xe `pm_runtime_get` around a CPU copy): the function is
    /// in D0 with a running GT, and the pool's CPU access open, until the
    /// returned guard drops. The default has no runtime PM to hold.
    fn cpu_vram_wakeref(&self) -> FsFuture<'_, Box<dyn core::any::Any + Send>> {
        Box::pin(async { Ok(Box::new(()) as Box<dyn core::any::Any + Send>) })
    }
    /// Cached physical BMG/LNL main-GT layout; no read-triggered hardware access.
    fn eu_stall_info(&self) -> Option<crate::intel_gpu_eu_stall::Info> {
        None
    }
    /// The GT owner serializes observation DMA with reset, power and MCR.
    fn eu_stall_control(
        &self,
        _session: Arc<crate::intel_gpu_eu_stall::Session>,
        _operation: crate::intel_gpu_eu_stall::Operation,
    ) -> FsFuture<'_, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// Cached main-GT OAG facts for this live epoch; no read-triggered I/O.
    fn oa_device(&self) -> Option<crate::intel_gpu_oa::Device> {
        None
    }
    /// The GT owner serializes OA programming and configuration jobs with
    /// reset, power and its other DMA owners.
    fn oa_control(
        &self,
        _session: Arc<crate::intel_gpu_oa::Session>,
        _request: crate::intel_gpu_oa::Request,
    ) -> FsFuture<'_, ()> {
        Box::pin(async { Err(FsError::NoDevice) })
    }
    /// Copy landed OA reports under the GT owner and advance the head.
    fn oa_read<'a>(
        &'a self,
        _session: Arc<crate::intel_gpu_oa::Session>,
        _output: &'a mut [u8],
        _blocking: bool,
    ) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::NoDevice) })
    }
    /// Stable ABI selection for this card, independent of temporary readiness.
    fn native_xe(&self) -> bool {
        false
    }
    /// This function's GT owner runs beside a display it preserves (the
    /// Lunar Lake display-20 route's `DisplayPreserving` profile), so its
    /// objects may be created for scanout. Default: headless or not an
    /// integrated Xe2 profile.
    fn display_preserving(&self) -> bool {
        false
    }
    fn device_facts(&self) -> Option<DeviceFacts> {
        None
    }
    /// Initialize unpublished owned VRAM under this card's retained power/GT
    /// owner: a trusted DG2 data/CCS BCS0 job, or bounded Xe2 WC CPU zeroing.
    /// A GPU job retains the complete graph through terminal completion or
    /// verified reset. The caller publishes no handle until the returned
    /// fence succeeds in `epoch`.
    fn clear_vram(
        &self,
        _object: Arc<crate::intel_gpu_gem::GemObject>,
        _epoch: u64,
    ) -> FsFuture<'_, Arc<CompletionFence>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// Revalidate terminal initialization and current whole-DPA ownership at
    /// actual handle publication. Only opted-in smallbar callers use this;
    /// unsupported backends cannot publish by returning a cached epoch.
    fn publish_vram<'a>(
        &'a self,
        _epoch: u64,
        _pool: Arc<crate::intel_gpu_vram::Vram>,
        _object: Arc<crate::intel_gpu_gem::GemObject>,
        _fence: Arc<CompletionFence>,
        _publish: VramPublish<'a>,
    ) -> FsFuture<'a, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// Submit a trusted retained copy under this card's current GT/PM owner.
    /// Err publishes no DMA; Ok transfers the private batch and both BOs to
    /// the GT until terminal completion/reset, independently of caller Drop.
    /// Callers exclude uncontrolled CPU aliases while the job is pending.
    fn copy_objects(
        &self,
        _request: crate::intel_gpu_exec::copy::CopyRequest,
        _epoch: u64,
    ) -> FsFuture<'_, Arc<CompletionFence>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// Nonblocking policy requests serviced only by the retained GT owner.
    fn power_controls(&self) -> Option<Arc<crate::intel_gpu_power_controls::PowerControls>> {
        None
    }
    /// Client-free compute partition changes serviced by the retained owner.
    fn ccs_control(&self) -> Option<Arc<crate::intel_gpu_ccs_control::Control>> {
        None
    }
    /// Copy bounded firmware logs into an owned diagnostic buffer while the
    /// retained GT excludes reset/power transitions. The file provider owns
    /// diagnostic authorization and rechecks it before every read.
    fn guc_log_snapshot(
        &self,
        _buffer: crate::intel_gpu_guc_log::CaptureBuffer,
    ) -> FsFuture<'_, crate::intel_gpu_guc_log::Snapshot> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// Attach one privileged stream under the real GT reset/power owner.
    fn guc_log_stream(
        &self,
        _session: Arc<crate::intel_gpu_guc_log::StreamSession>,
    ) -> FsFuture<'_, ()> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// Correlate a live engine counter with one supported CPU clock while the
    /// owner retains PCI D0, render forcewake and its reset mutex.
    fn engine_cycles(
        &self,
        _engine: crate::intel_gpu_engine::Engine,
        _clock: i32,
    ) -> FsFuture<'_, crate::intel_gpu_timestamp::EngineCycles> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// The same correlation for a published media GT (gt_id 1) engine, under
    /// the media GuC's GT1 wake and engine wells. Default: no media GT.
    fn media_engine_cycles(
        &self,
        _engine: crate::intel_gpu_engine::Engine,
        _clock: i32,
    ) -> FsFuture<'_, crate::intel_gpu_timestamp::EngineCycles> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    /// Err means nothing was queued. Ok transfers ownership to the GT even
    /// if the calling future/fd/context handle is subsequently dropped.
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>>;

    fn submit_with_output<'a>(
        &'a self,
        _context: Arc<UserContext>,
        _batch: UserBatch,
        _output: UserOutput<'a>,
    ) -> OutputFuture<'a> {
        Box::pin(async { Err(OutputError::Io(FsError::Unsupported)) })
    }
}

pub type OutputFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<CompletionFence>, OutputError>> + Send + 'a>>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OutputError {
    Io(FsError),
    Install(InstallFdError),
}
impl From<FsError> for OutputError {
    fn from(error: FsError) -> Self {
        Self::Io(error)
    }
}

/// A borrowed fault-aware output transaction. Install/copyout happens after
/// all fallible GT preparation and immediately before non-failing enqueue.
pub struct UserOutput<'a> {
    pub user: &'a dyn IoctlContext,
    pub address: u64,
    pub input: u32,
}
impl core::fmt::Debug for UserOutput<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserOutput")
            .field("address", &self.address)
            .field("input", &self.input)
            .finish_non_exhaustive()
    }
}
impl UserOutput<'_> {
    pub(crate) fn install(&self, fence: Arc<CompletionFence>) -> Result<(), InstallFdError> {
        self.user
            .install_sync_file(vec![fence], &mut |fd| {
                let value = u64::from(self.input) | ((fd as u32 as u64) << 32);
                self.user.write(self.address, &value.to_le_bytes())
            })
            .map(|_| ())
    }
}

/// Untrusted instructions can name only this immutable private PPGTT graph.
/// CPU aliases of leaf BOs remain untrusted; hardware nonsecure command
/// checking applies to every instruction, including nested batches.
#[derive(Debug)]
pub struct UserBatch(pub(crate) ResidentBatch);

#[derive(Debug)]
struct State {
    epoch: u64,
    busy: bool,
    banned: bool,
    valid: bool,
    image: Vec<u32>,
    last: Option<Arc<CompletionFence>>,
    lost_pending: u32,
    /// Jobs of this context that hung and were removed from their engine.
    guilty: u32,
    /// GuC SCHEDULING_PRIORITY (GUC_CLIENT_PRIORITY_*) and EXECUTION_QUANTUM
    /// (us) for the next request: native Xe queue properties, or an i915
    /// context's mapped ctx->sched.priority.
    policy: (u32, u32),
    /// The same pair for the job in flight, fixed at its claim except that
    /// a later request on this context raises its priority (queue_request).
    job_policy: (u32, u32),
    /// Saved (priority, timeslice) while an OA NO_PREEMPT stream holds
    /// this queue at timeslice 0 + preempt timeout 0 (Linux
    /// xe_oa_disable_preempt_timeslice, which sets both to 0 and restores
    /// the class defaults at disable). `Some` while the override is live;
    /// the live `policy` then carries timeslice 0 and this holds the
    /// user's own pair for the restore. `None` when no override is live.
    oa_saved: Option<(u32, u32)>,
    /// The OA query sampler registered on this context while a query-mode
    /// OAR/OAC stream holds it (set at OA enable, cleared at disable).
    /// `None` when no query-mode stream is live on this queue.
    query_sampler: Option<Arc<crate::intel_gpu_oa::QuerySampler>>,
    /// i915 requests queued and not yet staged, per GuC band.
    queued: [u32; 4],
    /// The band of the i915 request whose submission attempt is next to
    /// claim this context; serialized by `serial`.
    staged: Option<u32>,
    /// Immutable queue-create intent; retained with the private context image
    /// through repeated registration, cancellation and verified reset.
    low_latency: bool,
}

#[derive(Debug)]
struct ParallelPlacements {
    engines: Vec<crate::intel_gpu_engine::Engine>,
    lanes: Vec<crate::intel_gpu_engine::EngineSet>,
}

/// One live compatibility policy shared by all hardware members of a logical
/// i915 context. Jobs retain it after the namespace name is destroyed.
#[derive(Debug, Default)]
pub(crate) struct CapturePolicy(AtomicBool);
impl CapturePolicy {
    pub(crate) fn set(&self, value: u64) {
        self.0.store(value != 0, Ordering::Release);
    }
    pub(crate) fn protected(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct UserContext {
    /// Orders callers while allowing GT/timer tasks to run during waits.
    pub(crate) serial: Mutex<()>,
    engine: crate::intel_gpu_engine::Engine,
    placements: crate::intel_gpu_engine::EngineSet,
    parallel: Option<ParallelPlacements>,
    capture_policy: Option<Arc<CapturePolicy>>,
    state: IrqSafeSpinLock<State>,
}

impl UserContext {
    pub fn new() -> Arc<Self> {
        Self::for_engine(crate::intel_gpu_engine::Engine::Rcs0)
    }

    /// The engine is immutable: saved state belongs to one class's layout.
    pub fn for_engine(engine: crate::intel_gpu_engine::Engine) -> Arc<Self> {
        Self::with_placements(
            engine,
            crate::intel_gpu_engine::EngineSet::of(&[engine]),
            None,
            None,
        )
    }

    /// One hardware member of an i915 context whose ctx->sched.priority is
    /// `priority`.
    pub(crate) fn for_i915_engine(
        engine: crate::intel_gpu_engine::Engine,
        policy: Arc<CapturePolicy>,
        priority: i32,
    ) -> Arc<Self> {
        let context = Self::with_placements(
            engine,
            crate::intel_gpu_engine::EngineSet::of(&[engine]),
            None,
            Some(policy),
        );
        context.set_i915_priority(priority);
        context
    }

    /// Width-one GuC virtual context. The representative supplies only the
    /// class-compatible image layout; firmware selects each physical engine.
    pub(crate) fn for_placements(
        placements: crate::intel_gpu_engine::EngineSet,
    ) -> Result<Arc<Self>, FsError> {
        Self::placements_with_policy(placements, None)
    }

    pub(crate) fn for_i915_placements(
        placements: crate::intel_gpu_engine::EngineSet,
        policy: Arc<CapturePolicy>,
        priority: i32,
    ) -> Result<Arc<Self>, FsError> {
        let context = Self::placements_with_policy(placements, Some(policy))?;
        context.set_i915_priority(priority);
        Ok(context)
    }

    fn placements_with_policy(
        placements: crate::intel_gpu_engine::EngineSet,
        capture_policy: Option<Arc<CapturePolicy>>,
    ) -> Result<Arc<Self>, FsError> {
        let engine = placements.iter().next().ok_or(FsError::InvalidData)?;
        if placements
            .iter()
            .any(|candidate| candidate.xe_class() != engine.xe_class())
        {
            return Err(FsError::InvalidData);
        }
        Ok(Self::with_placements(
            engine,
            placements,
            None,
            capture_policy,
        ))
    }

    pub(crate) fn for_parallel(
        lanes: Vec<crate::intel_gpu_engine::EngineSet>,
    ) -> Result<Arc<Self>, FsError> {
        let first = lanes
            .first()
            .and_then(|set| set.iter().next())
            .ok_or(FsError::InvalidData)?;
        if !(2..=MAX_PARALLEL_WIDTH).contains(&lanes.len())
            || !(first.is_copy() || first.is_compute() || first.is_media())
            || lanes.iter().any(|set| {
                set.iter().next().is_none()
                    || set
                        .iter()
                        .any(|engine| engine.xe_class() != first.xe_class())
            })
        {
            return Err(FsError::InvalidData);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(lanes.len())
            .map_err(|_| FsError::OutOfMemory)?;
        owned.extend(
            lanes
                .iter()
                .map(|set| set.iter().next().expect("validated lane")),
        );
        let placements = lanes[0];
        Ok(Self::with_placements(
            first,
            placements,
            Some(ParallelPlacements {
                engines: owned,
                lanes,
            }),
            None,
        ))
    }

    fn with_placements(
        engine: crate::intel_gpu_engine::Engine,
        placements: crate::intel_gpu_engine::EngineSet,
        parallel: Option<ParallelPlacements>,
        capture_policy: Option<Arc<CapturePolicy>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            serial: Mutex::new(()),
            engine,
            placements,
            parallel,
            capture_policy,
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                busy: false,
                banned: false,
                valid: false,
                image: Vec::new(),
                last: None,
                lost_pending: 0,
                guilty: 0,
                policy: (GUC_PRIORITY_NORMAL, 1000),
                job_policy: (GUC_PRIORITY_NORMAL, 1000),
                oa_saved: None,
                query_sampler: None,
                queued: [0; 4],
                staged: None,
                low_latency: false,
            }),
        })
    }

    pub fn engine(&self) -> crate::intel_gpu_engine::Engine {
        self.engine
    }
    pub(crate) fn placements(&self) -> crate::intel_gpu_engine::EngineSet {
        self.placements
    }
    pub(crate) fn parallel(&self) -> Option<&[crate::intel_gpu_engine::Engine]> {
        self.parallel
            .as_ref()
            .map(|parallel| parallel.engines.as_slice())
    }
    pub(crate) fn parallel_placements(&self) -> Option<&[crate::intel_gpu_engine::EngineSet]> {
        self.parallel
            .as_ref()
            .map(|parallel| parallel.lanes.as_slice())
    }
    pub(crate) fn last(&self) -> Option<Arc<CompletionFence>> {
        self.state.lock().last.clone()
    }
    /// DRM_XE_EXEC_QUEUE_SET_PROPERTY_HANG_REPLAY_STATE: seed the context's saved
    /// image from the supplied user LRC buffer rather than golden state, matching
    /// Linux xe_lrc_create().
    pub(crate) fn init_hang_replay(&self, bytes: &[u8]) -> Result<(), FsError> {
        let words = bytes.len() / 4;
        let mut state = self.state.lock();
        if !state.image.is_empty() {
            return Err(FsError::InvalidData);
        }
        let byte_len = words * 4;
        STATE_BYTES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(byte_len).filter(|n| *n <= MAX_STATE_BYTES)
            })
            .map_err(|_| FsError::OutOfMemory)?;
        let mut image = Vec::new();
        if image.try_reserve_exact(words).is_err() {
            STATE_BYTES.fetch_sub(byte_len, Ordering::AcqRel);
            return Err(FsError::OutOfMemory);
        }
        for chunk in bytes.chunks_exact(4) {
            image.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }
        state.image = image;
        state.valid = true;
        Ok(())
    }
    /// GuC priority 1..3 and the EXECUTION_QUANTUM (0x2001) KLV value in
    /// microseconds: init_policies passes q->sched_props.timeslice_us
    /// unchanged, so the whole exec_queue_set_timeslice range reaches GuC.
    /// Like Linux's setters it never refuses a claimed context: the policy
    /// applies from the next registration, and a job in flight keeps the
    /// policy it was claimed with.
    pub(crate) fn configure_schedule(&self, priority: u32, timeslice: u32) -> Result<(), FsError> {
        use crate::intel_gpu_xe::{TIMESLICE_MAX_US, TIMESLICE_MIN_US};
        if !(GUC_PRIORITY_HIGH..=GUC_PRIORITY_NORMAL).contains(&priority)
            || !(TIMESLICE_MIN_US..=TIMESLICE_MAX_US).contains(&u64::from(timeslice))
        {
            return Err(FsError::InvalidData);
        }
        // While an OA NO_PREEMPT override is live the timeslice the GuC
        // sees stays 0; record the user's new pair as the saved values so
        // the restore applies them, and apply the priority (which the
        // override does not touch) to the live pair at once.
        let mut state = self.state.lock();
        if let Some(saved) = state.oa_saved.as_mut() {
            *saved = (priority, timeslice);
            state.policy.0 = priority;
        } else {
            state.policy = (priority, timeslice);
        }
        Ok(())
    }
    /// Store an i915 ctx->sched.priority (guc_context_init and add_to_context
    /// map it through map_i915_prio_to_guc_prio). Like
    /// i915_gem_context.c::set_priority it sends GuC nothing: requests
    /// queued from now on carry it, and earlier ones keep their own.
    /// While an OA NO_PREEMPT override is live the saved pair takes the
    /// new priority too, so the restore does not clobber it.
    pub(crate) fn set_i915_priority(&self, priority: i32) {
        let mapped = map_i915_prio_to_guc_prio(priority);
        let mut state = self.state.lock();
        if let Some(saved) = state.oa_saved.as_mut() {
            saved.0 = mapped;
        }
        state.policy.0 = mapped;
    }
    /// Whether an OA NO_PREEMPT override is live on this context.
    pub(crate) fn oa_no_preempt(&self) -> bool {
        self.state.lock().oa_saved.is_some()
    }
    /// Apply the OA NO_PREEMPT schedule override (Linux
    /// xe_oa_disable_preempt_timeslice, which sets timeslice and preempt
    /// timeout to 0): save the user's (priority, timeslice) and hold the
    /// live timeslice at 0, so the next claim's GuC Policy KLVs carry
    /// EXECUTION_QUANTUM 0 and preempt timeout 0. Idempotent: a second
    /// apply while the override is live keeps the original saved pair.
    /// The user-facing setter rejects timeslice 0, exactly as Linux's
    /// userspace setter rejects it while the OA path sets it directly,
    /// so this bypasses `configure_schedule`'s range check on purpose.
    pub(crate) fn oa_apply_no_preempt(&self) {
        let mut state = self.state.lock();
        if state.oa_saved.is_none() {
            state.oa_saved = Some(state.policy);
            state.policy.1 = 0;
        }
    }
    /// Restore the schedule an OA NO_PREEMPT override held (Linux
    /// xe_oa_enable_preempt_timeslice): the saved (priority, timeslice)
    /// becomes live again, so the next claim's GuC Policy KLVs carry the
    /// user's own quantum and the engine-class preempt timeout. Linux
    /// restores the class defaults, which would discard a user-set
    /// quantum; NARF restores the saved pair instead, so a queue that
    /// was reconfigured while the override was live keeps its newest
    /// setting (see `configure_schedule`). Idempotent.
    pub(crate) fn oa_restore_no_preempt(&self) {
        let mut state = self.state.lock();
        if let Some(saved) = state.oa_saved.take() {
            state.policy = saved;
        }
    }
    /// The GuC priority and execution quantum a request queued now would
    /// carry. Test-only: the production schedule surface is
    /// `configure_schedule` (which rejects timeslice 0) plus the OA
    /// override above.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn schedule_for_test(&self) -> (u32, u32) {
        self.state.lock().policy
    }
    /// Register or clear the OA query sampler on this context. Set at OA
    /// enable for a query-mode stream, cleared at disable (and on
    /// teardown), so the exec path emits one MI_REPORT_PERF_COUNT per
    /// batch only while the stream is live.
    pub(crate) fn set_query_sampler(
        &self,
        sampler: Option<Arc<crate::intel_gpu_oa::QuerySampler>>,
    ) {
        self.state.lock().query_sampler = sampler;
    }
    /// The OA query sampler registered on this context, if a query-mode
    /// OAR/OAC stream holds it.
    pub(crate) fn query_sampler(&self) -> Option<Arc<crate::intel_gpu_oa::QuerySampler>> {
        self.state.lock().query_sampler.clone()
    }
    /// The GuC priority a request queued now would carry.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn guc_priority(&self) -> u32 {
        self.state.lock().policy.0
    }
    /// Queue an i915 request at the context's current priority
    /// (rq->sched.attr from ctx->sched), counted per band until it is staged
    /// for its claim, as add_to_context counts ce->guc_state.prio_count. It
    /// depends on every earlier job on this timeline:
    /// i915_scheduler.c::__i915_schedule bumps them to its priority, and
    /// guc_bump_inflight_request_prio raises a job's GuC priority only when
    /// the band is higher (a lower value), so no job is ever demoted. A job
    /// in flight takes the raise now; one not yet claimed takes it at claim.
    pub(crate) fn queue_request(self: &Arc<Self>) -> QueuedRequest {
        let band = {
            let mut state = self.state.lock();
            let band = state.policy.0;
            let count = &mut state.queued[band as usize];
            *count = count.saturating_add(1);
            if state.busy && band < state.job_policy.0 {
                state.job_policy.0 = band;
            }
            band
        };
        QueuedRequest {
            context: self.clone(),
            band,
            staged: false,
        }
    }
    /// Configure only before this unpublished context has ever been claimed.
    /// No runtime ioctl mutates this create-only flag.
    pub(crate) fn configure_low_latency(&self) -> Result<(), FsError> {
        let mut state = self.state.lock();
        if state.epoch != 0 || state.busy {
            return Err(FsError::Busy);
        }
        state.low_latency = true;
        Ok(())
    }
    pub(crate) fn banned(&self) -> bool {
        self.state.lock().banned
    }
    /// Close admission without fabricating terminal GPU completion.
    pub(crate) fn request_ban(&self) {
        self.state.lock().banned = true;
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn busy(&self) -> bool {
        self.state.lock().busy
    }
    /// One word of the context's saved register image, as `restore` copies
    /// it into a fresh LRC image at 4096 + index * 4: index 3 is the
    /// RING_CONTEXT_CONTROL value slot (the image's first `reg_offsets`
    /// group names that register first). `None` only before the first claim
    /// allocates the image; after a claim with no capture yet it reads the
    /// allocated zero.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn saved_word(&self, index: usize) -> Option<u32> {
        self.state.lock().image.get(index).copied()
    }
    pub(crate) fn can_rebind(&self) -> bool {
        let state = self.state.lock();
        state.epoch == 0 && !state.busy
    }
    /// i915 `batch_active` / `batch_pending`: jobs this context lost because
    /// they hung (guilty) and because a full GT reset took them (innocent;
    /// no guilt is guessed for a full reset).
    pub(crate) fn reset_stats(&self) -> (u32, u32) {
        let state = self.state.lock();
        (state.guilty, state.lost_pending)
    }
    pub(crate) fn check_epoch(&self, epoch: u64) -> Result<(), FsError> {
        let mut state = self.state.lock();
        Self::check_state_epoch(&mut state, epoch)
    }

    fn check_state_epoch(state: &mut State, epoch: u64) -> Result<(), FsError> {
        if state.epoch != 0 && state.epoch != epoch && !state.banned {
            if state.busy {
                return Err(FsError::WouldBlock);
            }
            state.banned = true;
        }
        if state.banned {
            Err(io_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn claim(self: &Arc<Self>, epoch: u64, pages: u32) -> Result<ContextClaim, FsError> {
        let mut state = self.state.lock();
        Self::check_state_epoch(&mut state, epoch)?;
        if state.busy || state.last.as_ref().is_some_and(|f| f.result().is_none()) {
            return Err(FsError::WouldBlock);
        }
        let words = pages
            .checked_sub(1)
            .filter(|n| *n != 0 && *n <= 13)
            .ok_or(FsError::InvalidData)? as usize
            * 1024
            * self.parallel().map_or(1, <[_]>::len);
        if state.image.is_empty() {
            let bytes = words * 4;
            STATE_BYTES
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    n.checked_add(bytes).filter(|n| *n <= MAX_STATE_BYTES)
                })
                .map_err(|_| FsError::OutOfMemory)?;
            if state.image.try_reserve_exact(words).is_err() {
                STATE_BYTES.fetch_sub(bytes, Ordering::AcqRel);
                return Err(FsError::OutOfMemory);
            }
            state.image.resize(words, 0);
        }
        if state.image.len() != words {
            return Err(io_error());
        }
        state.busy = true;
        // The staged i915 request's own band, raised by every request queued
        // behind it (update_context_prio takes the highest band counted);
        // any other claim takes the stored policy.
        let own = state.staged.take().unwrap_or(state.policy.0);
        let behind = state
            .queued
            .iter()
            .position(|count| *count != 0)
            .map_or(own, |band| band as u32);
        state.job_policy = (own.min(behind), state.policy.1);
        Ok(ContextClaim {
            context: self.clone(),
            epoch,
            published: false,
        })
    }
}

impl Drop for UserContext {
    fn drop(&mut self) {
        STATE_BYTES.fetch_sub(self.state.lock().image.len() * 4, Ordering::AcqRel);
    }
}

/// An i915 execbuffer request between its ioctl and its claim
/// (UserContext::queue_request).
#[derive(Debug)]
pub(crate) struct QueuedRequest {
    context: Arc<UserContext>,
    band: u32,
    staged: bool,
}
impl QueuedRequest {
    /// Before each submission attempt, with the context's `serial` held:
    /// this request is the one the next claim takes, at its own band raised
    /// by the requests still queued behind it.
    pub(crate) fn stage(&mut self) {
        let mut state = self.context.state.lock();
        if !self.staged {
            let count = &mut state.queued[self.band as usize];
            *count = count.saturating_sub(1);
            self.staged = true;
        }
        state.staged = Some(self.band);
    }
}
impl Drop for QueuedRequest {
    /// An unstaged request that fails or is abandoned stops counting. A
    /// staged band that no claim took is replaced by the next request's
    /// stage before any later claim.
    fn drop(&mut self) {
        if !self.staged {
            let mut state = self.context.state.lock();
            let count = &mut state.queued[self.band as usize];
            *count = count.saturating_sub(1);
        }
    }
}

pub(crate) struct ContextClaim {
    context: Arc<UserContext>,
    epoch: u64,
    published: bool,
}
impl ContextClaim {
    pub(crate) fn placements(&self) -> crate::intel_gpu_engine::EngineSet {
        self.context.placements
    }
    pub(crate) fn parallel(&self) -> Option<&[crate::intel_gpu_engine::Engine]> {
        self.context.parallel()
    }
    pub(crate) fn parallel_placements(&self) -> Option<&[crate::intel_gpu_engine::EngineSet]> {
        self.context.parallel_placements()
    }
    /// The OA query sampler registered on this context, if a query-mode
    /// OAR/OAC stream holds it. The exec path reads this at submit time
    /// to emit one MI_REPORT_PERF_COUNT per batch.
    pub(crate) fn query_sampler(&self) -> Option<Arc<crate::intel_gpu_oa::QuerySampler>> {
        self.context.query_sampler()
    }
    pub(crate) fn restore(&self, image: &impl GpuBacking) {
        self.restore_lane(image, 0);
    }
    pub(crate) fn restore_lane(&self, image: &impl GpuBacking, lane: usize) {
        let state = self.context.state.lock();
        if state.valid {
            let words = state.image.len() / self.context.parallel().map_or(1, <[_]>::len);
            for (i, word) in state.image[lane * words..(lane + 1) * words]
                .iter()
                .enumerate()
            {
                image.write32(4096 + i as u64 * 4, *word);
            }
        }
    }
    pub(crate) fn publish(mut self, fence: Arc<CompletionFence>) -> UserJob {
        {
            let mut state = self.context.state.lock();
            state.epoch = self.epoch;
            state.last = Some(fence);
        }
        self.published = true;
        UserJob {
            context: self.context.clone(),
            epoch: self.epoch,
        }
    }
}
impl Drop for ContextClaim {
    fn drop(&mut self) {
        if !self.published {
            self.context.state.lock().busy = false;
        }
    }
}

pub(crate) struct UserJob {
    context: Arc<UserContext>,
    epoch: u64,
}
impl UserJob {
    pub(crate) fn diagnostic_protected(&self) -> bool {
        self.context
            .capture_policy
            .as_ref()
            .is_some_and(|policy| policy.protected())
    }
    /// GuC priority, execution quantum and low-latency intent of this job.
    pub(crate) fn policy(&self) -> (u32, u32, bool) {
        let state = self.context.state.lock();
        (state.job_policy.0, state.job_policy.1, state.low_latency)
    }
    /// Whether an OA NO_PREEMPT override is live on this job's context.
    /// The GuC Policy KLVs read this to emit preempt timeout 0 while the
    /// override holds, and the engine-class default once it is restored.
    pub(crate) fn oa_no_preempt(&self) -> bool {
        self.context.oa_no_preempt()
    }
    /// This job's current GuC priority, raised by later submissions.
    pub(crate) fn priority(&self) -> u32 {
        self.context.state.lock().job_policy.0
    }
    /// Called only after deregistration, exact-head/breadcrumb proof and the
    /// final TLB ACK, with device writes synchronized for the CPU.
    pub(crate) fn capture(&self, image: &impl GpuBacking, header: u32) -> Result<(), FsError> {
        self.capture_lanes(core::iter::once(image), header)
    }
    pub(crate) fn capture_lanes<'a, B: GpuBacking + 'a>(
        &self,
        images: impl Iterator<Item = &'a B> + Clone,
        header: u32,
    ) -> Result<(), FsError> {
        let mut state = self.context.state.lock();
        let count = self.context.parallel().map_or(1, <[_]>::len);
        if state.epoch != self.epoch
            || !state.busy
            || images.clone().count() != count
            || images.clone().any(|image| image.read32(4100) != header)
        {
            return Err(io_error());
        }
        let words = state.image.len() / count;
        for (lane, image) in images.enumerate() {
            for (i, word) in state.image[lane * words..(lane + 1) * words]
                .iter_mut()
                .enumerate()
            {
                *word = image.read32(4096 + i as u64 * 4);
            }
        }
        state.valid = true;
        Ok(())
    }
    /// The job hung and was removed from its engine: its state is never
    /// captured, and the context is banned as Linux bans the exec queue.
    pub(crate) fn finish_hung(self) {
        let mut state = self.context.state.lock();
        state.busy = false;
        state.banned = true;
        state.valid = false;
        state.guilty = state.guilty.saturating_add(1);
    }
    pub(crate) fn finish(self, reset: bool) {
        let mut state = self.context.state.lock();
        state.busy = false;
        if reset {
            state.banned = true;
            state.valid = false;
            state.lost_pending = state.lost_pending.saturating_add(1);
        }
    }
}
