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
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use narf_filesystem::{FsError, FsFuture};
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
}

pub trait UserBackend: core::fmt::Debug + Send + Sync {
    fn status(&self) -> Option<UserStatus>;
    /// Err means nothing was queued. Ok transfers ownership to the GT even
    /// if the calling future/fd/context handle is subsequently dropped.
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>>;
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
}

#[derive(Debug)]
pub struct UserContext {
    /// Orders callers while allowing GT/timer tasks to run during waits.
    pub(crate) serial: Mutex<()>,
    state: IrqSafeSpinLock<State>,
}

impl UserContext {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            serial: Mutex::new(()),
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                busy: false,
                banned: false,
                valid: false,
                image: Vec::new(),
                last: None,
                lost_pending: 0,
            }),
        })
    }

    pub(crate) fn last(&self) -> Option<Arc<CompletionFence>> {
        self.state.lock().last.clone()
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn busy(&self) -> bool {
        self.state.lock().busy
    }
    pub(crate) fn can_rebind(&self) -> bool {
        let state = self.state.lock();
        state.epoch == 0 && !state.busy
    }
    pub(crate) fn reset_stats(&self) -> (u32, u32) {
        let state = self.state.lock();
        // No GuC fault attribution is available yet. Like i915's innocent
        // reset accounting, report affected requests without guessing guilt.
        (0, state.lost_pending)
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
    /// Called only after deregistration, exact-head/breadcrumb proof and the
    /// final TLB ACK, with device writes synchronized for the CPU.
    pub(crate) fn capture(&self, image: &impl GpuBacking) -> Result<(), FsError> {
        let mut state = self.context.state.lock();
        if state.epoch != self.epoch || !state.busy || image.read32(4100) != 0x1108101d {
            return Err(io_error());
        }
        for (i, word) in state.image.iter_mut().enumerate() {
            *word = image.read32(4096 + i as u64 * 4);
        }
        state.valid = true;
        Ok(())
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
