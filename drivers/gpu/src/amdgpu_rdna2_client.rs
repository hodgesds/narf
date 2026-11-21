//! The engine owner behind the RDNA2 client path.
//!
//! `amdgpu_navi22_cs` serves an RDNA2 card's clients on the verified kernel
//! queues of one owner:
//! - Navi22's cold boot, retained by `amdgpu_navi22_platform`;
//! - Raphael's graphics coordinator, held by `amdgpu_platform`'s display
//!   owner beside the PSP session that loaded its firmware.
//!
//! Both drive the same queue owners (`cp::Gfx`, `kiq::Compute`,
//! `sdma_queues::Sdma`). [`Owner`] is the part of them a client job needs,
//! and [`lock`] takes the owner of whichever card registered. One RDNA2 card
//! serves clients at a time: the submitter, its VMIDs and the fence
//! generation are single-instance.
use crate::amdgpu_cp_navi22 as cp;
use crate::amdgpu_navi22_boot::Error as BootError;
use crate::amdgpu_navi22_submit::{Ib, MediaRing, Ring, RingState, VmRef};
use core::sync::atomic::{AtomicU8, Ordering};

/// What a client job needs from its engine owner, under that owner's lock.
pub(crate) trait Owner: Send {
    /// `amdgpu_ib_schedule` on a verified kernel queue: the job's sequence.
    /// `Busy` is a full ring (wait for its oldest job), `Invalid` a request
    /// the queue refuses; anything else is the device gone.
    fn submit(
        &mut self,
        ring: Ring,
        state: &mut RingState,
        vm: VmRef,
        context: u64,
        ibs: &[Ib],
    ) -> Result<u32, cp::Error>;
    /// `ring`'s fence pair; `.1` is the oldest job still in flight.
    fn fences(&mut self, ring: Ring) -> Result<(u32, u32), cp::Error>;
}

/// Which owner [`lock`] takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    Navi22,
    Raphael,
}
static BACKEND: AtomicU8 = AtomicU8::new(0);
const NAVI22: u8 = 0;
const RAPHAEL: u8 = 1;

/// Record the owner a submitter is about to register for.
pub(crate) fn set_backend(backend: Backend) {
    let value = match backend {
        Backend::Navi22 => NAVI22,
        Backend::Raphael => RAPHAEL,
    };
    BACKEND.store(value, Ordering::Release);
}
pub(crate) fn backend() -> Backend {
    match BACKEND.load(Ordering::Acquire) {
        RAPHAEL => Backend::Raphael,
        _ => Backend::Navi22,
    }
}

/// The locked owner of the registered card.
pub(crate) enum Guard {
    Navi22(narf_lib::mutex::MutexGuard<'static, Option<crate::amdgpu_navi22_boot::ColdBoot>>),
    Raphael(crate::amdgpu_platform::Graphics),
}
impl Guard {
    /// The owner, while one exists and holds its queues.
    pub(crate) fn owner(&mut self) -> Option<&mut dyn Owner> {
        match self {
            Self::Navi22(guard) => guard.as_mut().map(|boot| boot as &mut dyn Owner),
            Self::Raphael(guard) => guard.get().map(|boot| boot as &mut dyn Owner),
        }
    }
    /// The media owner, with what its power transitions need: Raphael's
    /// coordinator comes with the display loader's PSP session, the one that
    /// loaded VCN and takes its DPG register lists.
    pub(crate) fn media(&mut self) -> Option<Media<'_>> {
        match self {
            Self::Navi22(guard) => guard.as_mut().map(Media::Navi22),
            Self::Raphael(guard) => guard.media().map(|(boot, psp)| Media::Raphael(boot, psp)),
        }
    }
}

/// The media half of a locked owner, for `amdgpu_vcn_navi22_cs` and the VCN
/// idle work. Its methods are Navi22's cold-boot ones, errors included, so
/// those callers read the same either way.
pub(crate) enum Media<'a> {
    Navi22(&'a mut crate::amdgpu_navi22_boot::ColdBoot),
    Raphael(
        &'a mut crate::amdgpu_raphael_boot::ColdBoot,
        &'a mut crate::amdgpu_psp_ring::Psp,
    ),
}
impl Media<'_> {
    /// `amdgpu_vcn_ring_begin_use`, then the job on `ring`: its sequence.
    pub(crate) async fn submit_media(
        &mut self,
        ring: MediaRing,
        vm: VmRef,
        ibs: &[Ib],
        copies: &[alloc::vec::Vec<u32>],
    ) -> Result<u32, BootError> {
        match self {
            Self::Navi22(boot) => boot.submit_media(ring, vm, ibs, copies).await,
            Self::Raphael(boot, psp) => boot
                .submit_media(psp, ring, vm, ibs, copies)
                .await
                .map_err(BootError::Media),
        }
    }
    /// (last completed, throttle) sequences of client media `ring`.
    pub(crate) fn media_fences(&mut self, ring: MediaRing) -> Result<(u32, u32), BootError> {
        match self {
            Self::Navi22(boot) => boot.media_fences(ring),
            Self::Raphael(boot, _) => boot.media_fences(ring).map_err(BootError::Media),
        }
    }
    /// The VCN idle work: gate VCN once its rings are idle.
    pub(crate) async fn idle_media(&mut self, now: u64) -> Result<bool, BootError> {
        match self {
            Self::Navi22(boot) => boot.idle_media(now).await,
            Self::Raphael(boot, psp) => boot.idle_media(psp, now).await.map_err(BootError::Media),
        }
    }
    /// When the idle work should look again; `None` until the next use.
    pub(crate) fn media_idle_recheck(&self, now: u64) -> Option<u64> {
        match self {
            Self::Navi22(boot) => boot.media_idle_recheck(now),
            Self::Raphael(boot, _) => boot.media_idle_recheck(now),
        }
    }
}
/// Lock the registered card's owner. Never held across a fence wait.
pub(crate) async fn lock() -> Guard {
    match backend() {
        Backend::Navi22 => Guard::Navi22(crate::amdgpu_navi22_platform::owner().await),
        Backend::Raphael => Guard::Raphael(crate::amdgpu_platform::graphics_owner().await),
    }
}

impl Owner for crate::amdgpu_navi22_boot::ColdBoot {
    fn submit(
        &mut self,
        ring: Ring,
        state: &mut RingState,
        vm: VmRef,
        context: u64,
        ibs: &[Ib],
    ) -> Result<u32, cp::Error> {
        // Only a queue's own refusal is reported as one; an owner that is
        // not ready, or has no queues, is the device gone.
        match crate::amdgpu_navi22_boot::ColdBoot::submit(self, ring, state, vm, context, ibs) {
            Ok(seq) => Ok(seq),
            Err(crate::amdgpu_navi22_boot::Error::Queues(error)) => Err(error),
            Err(_) => Err(cp::Error::DeviceGone),
        }
    }
    fn fences(&mut self, ring: Ring) -> Result<(u32, u32), cp::Error> {
        crate::amdgpu_navi22_boot::ColdBoot::fences(self, ring).map_err(|_| cp::Error::DeviceGone)
    }
}

impl Owner for crate::amdgpu_raphael_boot::ColdBoot {
    fn submit(
        &mut self,
        ring: Ring,
        state: &mut RingState,
        vm: VmRef,
        context: u64,
        ibs: &[Ib],
    ) -> Result<u32, cp::Error> {
        crate::amdgpu_raphael_boot::ColdBoot::submit(self, ring, state, vm, context, ibs)
    }
    fn fences(&mut self, ring: Ring) -> Result<(u32, u32), cp::Error> {
        crate::amdgpu_raphael_boot::ColdBoot::fences(self, ring)
    }
}
