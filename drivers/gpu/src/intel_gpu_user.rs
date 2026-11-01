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
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::{future::Future, pin::Pin};
use narf_filesystem::{FsError, FsFuture, InstallFdError, IoctlContext};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
static STATE_BYTES: AtomicUsize = AtomicUsize::new(0);
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn next_epoch() -> u64 {
    NEXT_EPOCH
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .expect("Intel GT epoch exhausted")
}

pub(crate) fn io_error() -> FsError {
    FsError::Io(narf_block::BlockError::IOError)
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

/// Observed PF/graphics-GT facts for the native Xe discovery ABI. Published
/// before live admission; a PCI ID alone cannot supply the clock or GMD step.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceFacts {
    pub revision: u8,
    pub graphics_version: u16,
    pub graphics_step: u8,
    pub reference_clock: u32,
}

pub trait UserBackend: core::fmt::Debug + Send + Sync {
    fn status(&self) -> Option<UserStatus>;
    /// Stable ABI selection for this card, independent of temporary readiness.
    fn native_xe(&self) -> bool {
        false
    }
    fn device_facts(&self) -> Option<DeviceFacts> {
        None
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
    /// Correlate a live engine counter with one supported CPU clock while the
    /// owner retains PCI D0, render forcewake and its reset mutex.
    fn engine_cycles(
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
    policy: (u32, u32),
}

#[derive(Debug)]
pub struct UserContext {
    /// Orders callers while allowing GT/timer tasks to run during waits.
    pub(crate) serial: Mutex<()>,
    engine: crate::intel_gpu_engine::Engine,
    placements: crate::intel_gpu_engine::EngineSet,
    state: IrqSafeSpinLock<State>,
}

impl UserContext {
    pub fn new() -> Arc<Self> {
        Self::for_engine(crate::intel_gpu_engine::Engine::Rcs0)
    }

    /// The engine is immutable: saved state belongs to one class's layout.
    pub fn for_engine(engine: crate::intel_gpu_engine::Engine) -> Arc<Self> {
        Self::with_placements(engine, crate::intel_gpu_engine::EngineSet::of(&[engine]))
    }

    /// Width-one GuC virtual context. The representative supplies only the
    /// class-compatible image layout; firmware selects each physical engine.
    pub(crate) fn for_placements(
        placements: crate::intel_gpu_engine::EngineSet,
    ) -> Result<Arc<Self>, FsError> {
        let engine = placements.iter().next().ok_or(FsError::InvalidData)?;
        if placements
            .iter()
            .any(|candidate| candidate.xe_class() != engine.xe_class())
        {
            return Err(FsError::InvalidData);
        }
        Ok(Self::with_placements(engine, placements))
    }

    fn with_placements(
        engine: crate::intel_gpu_engine::Engine,
        placements: crate::intel_gpu_engine::EngineSet,
    ) -> Arc<Self> {
        Arc::new(Self {
            serial: Mutex::new(()),
            engine,
            placements,
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                busy: false,
                banned: false,
                valid: false,
                image: Vec::new(),
                last: None,
                lost_pending: 0,
                guilty: 0,
                policy: (3, 1000),
            }),
        })
    }

    pub fn engine(&self) -> crate::intel_gpu_engine::Engine {
        self.engine
    }
    pub(crate) fn placements(&self) -> crate::intel_gpu_engine::EngineSet {
        self.placements
    }
    pub(crate) fn last(&self) -> Option<Arc<CompletionFence>> {
        self.state.lock().last.clone()
    }
    pub(crate) fn configure_schedule(&self, priority: u32, timeslice: u32) -> Result<(), FsError> {
        if !matches!(priority, 2 | 3) || !(1..=100_000).contains(&timeslice) {
            return Err(FsError::InvalidData);
        }
        let mut state = self.state.lock();
        if state.epoch != 0 || state.busy {
            return Err(FsError::Busy);
        }
        state.policy = (priority, timeslice);
        Ok(())
    }
    pub(crate) fn banned(&self) -> bool {
        self.state.lock().banned
    }
    /// Close admission without fabricating terminal GPU completion.
    pub(crate) fn request_ban(&self) {
        self.state.lock().banned = true;
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn busy(&self) -> bool {
        self.state.lock().busy
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
            * 1024;
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

pub(crate) struct ContextClaim {
    context: Arc<UserContext>,
    epoch: u64,
    published: bool,
}
impl ContextClaim {
    pub(crate) fn placements(&self) -> crate::intel_gpu_engine::EngineSet {
        self.context.placements
    }
    pub(crate) fn restore(&self, image: &impl GpuBacking) {
        let state = self.context.state.lock();
        if state.valid {
            for (i, word) in state.image.iter().enumerate() {
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
    pub(crate) fn policy(&self) -> (u32, u32) {
        self.context.state.lock().policy
    }
    /// Called only after deregistration, exact-head/breadcrumb proof and the
    /// final TLB ACK, with device writes synchronized for the CPU.
    pub(crate) fn capture(&self, image: &impl GpuBacking, header: u32) -> Result<(), FsError> {
        let mut state = self.context.state.lock();
        if state.epoch != self.epoch || !state.busy || image.read32(4100) != header {
            return Err(io_error());
        }
        for (i, word) in state.image.iter_mut().enumerate() {
            *word = image.read32(4096 + i as u64 * 4);
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
