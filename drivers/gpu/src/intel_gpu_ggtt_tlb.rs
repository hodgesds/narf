//! GuC GGTT TLB invalidation for the shared GGTT arena.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! - xe_ggtt.c::xe_ggtt_invalidate runs after every GGTT update (initial
//!   clear, insert, remove, VF assign/load). It reads VF_CAP_REG as a barrier,
//!   then ggtt_invalidate_gt_tlb invalidates the GGTT TLB of the tile's primary
//!   GT and of its media GT. ggtt_node_remove clears the PTEs and removes the
//!   node under the GGTT lock, then invalidates before the caller frees the BO
//!   backing (xe_ggtt_remove_bo).
//! - xe_tlb_inval.c::xe_tlb_inval_ggtt issues one fence and waits for it.
//!   xe_tlb_inval_fence_prep takes the per-GT seqno, which starts at 1, wraps
//!   at TLB_INVALIDATION_SEQNO_MAX (0x100000) and skips 0.
//! - xe_guc_tlb_inval.c::send_tlb_inval_ggtt picks the transport. With
//!   xe_guc_ct_enabled && submission_state.enabled it sends H2G
//!   XE_GUC_ACTION_TLB_INVALIDATION (0x7000) {seqno,
//!   MAKE_INVAL_OP(XE_GUC_TLB_INVAL_GUC)}, where MAKE_INVAL_OP is type 3,
//!   HEAVY mode and FLUSH_CACHE (0x80000003).
//!   Otherwise, with uC enabled, it writes PVC_GUC_TLB_INV_DESC1/DESC0 when
//!   GRAPHICS_VER >= 20, else GUC_TLB_INV_CR, under GT forcewake. The MMIO path
//!   returns -ECANCELED, which signals the fence at once.
//! - xe_guc_ct.c routes G2H XE_GUC_ACTION_TLB_INVALIDATION_DONE (0x7001),
//!   whose payload is exactly the seqno (xe_guc_tlb_inval_done_handler).
//! - xe_guc_tlb_inval.c::tlb_inval_timeout_delay: HZ/4 plus twice
//!   xe_guc_ct_queue_proc_time_jiffies, one second per 4 KiB of H2G CTB.
//!   NARF's H2G CTB is 4 KiB, so the bound is 2.25 s from issue.
//!
//! NARF differences, each fail-closed:
//! - The arena is an IRQ-safe spin lock, and it is also entered from the
//!   scheduler while that scheduler holds the CT. It cannot send or wait. Each
//!   PTE burst therefore advances a generation. MMIO-mode GuCs are invalidated
//!   at once under the arena lock, as before. A CT-mode GuC's scheduler sends
//!   the TLB_INVALIDATION from its own poll, with no arena lock held.
//! - Removal retains both the GGTT range and its frames until every GuC has a
//!   completed invalidation issued after the clear. Linux returns the range
//!   to drm_mm before invalidating, but frees the BO only after the wait.
//! - One request per GuC is in flight. It covers every update published
//!   before it was sent, so later updates wait for the next request.
//! - On timeout Linux signals the fence -ETIME and proceeds. NARF keeps the
//!   range and fails the scheduler with `Timeout`, so the GT is lost and goes
//!   through reset. Only a proven GuC reset releases the range.
//! - The scheduler's per-context invalidations use request stamps from the
//!   same GuC seqno space. A GGTT seqno skips any live context stamp, and new
//!   context stamps skip the in-flight GGTT seqno.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_guc::GuCMessage;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// XE_GUC_ACTION_TLB_INVALIDATION.
pub(crate) const ACTION: u16 = 0x7000;
/// XE_GUC_ACTION_TLB_INVALIDATION_DONE.
pub(crate) const DONE: u32 = 0x7001;
/// MAKE_INVAL_OP(XE_GUC_TLB_INVAL_GUC): type 3, HEAVY mode, FLUSH_CACHE.
pub(crate) const OP_GUC: u32 = 0x8000_0003;
/// TLB_INVALIDATION_SEQNO_MAX.
pub(crate) const SEQNO_MAX: u32 = 0x10_0000;
/// The transport's H2G CTB: 1024 dwords.
const H2G_BYTES: u64 = 4096;
/// tlb_inval_timeout_delay: HZ/4 + 2 * (CTB_H2G_BUFFER_SIZE / SZ_4K) * HZ.
pub(crate) const TIMEOUT_NS: u64 = 250_000_000 + 2 * (H2G_BYTES / 4096) * 1_000_000_000;

const VF_CAP_REG: u64 = 0x1901f8;
const GUC_TLB_INV_CR: u64 = 0xcee8;
const GUC_TLB_INV_CR_INVALIDATE: u32 = 1 << 0;
const PVC_GUC_TLB_INV_DESC0: u64 = 0xcf7c;
const PVC_GUC_TLB_INV_DESC0_VALID: u32 = 1 << 0;
const PVC_GUC_TLB_INV_DESC1: u64 = 0xcf80;
const PVC_GUC_TLB_INV_DESC1_INVALIDATE: u32 = 1 << 6;

/// xe_ggtt.c::xe_ggtt_invalidate's barrier, read once before the GT TLBs.
pub(crate) fn barrier(root: &impl MmioWindow) {
    let _ = root.read32(VF_CAP_REG);
}

/// send_tlb_inval_ggtt's MMIO branch for one GT through that GT's register
/// view. `xe2` is GRAPHICS_VER >= 20 (PVC is not a NARF platform). The
/// caller holds the GT wake. The trailing read posts the write.
pub(crate) fn invalidate_mmio(gt: &(impl MmioWindow + ?Sized), xe2: bool) {
    if xe2 {
        gt.write32(PVC_GUC_TLB_INV_DESC1, PVC_GUC_TLB_INV_DESC1_INVALIDATE);
        gt.write32(PVC_GUC_TLB_INV_DESC0, PVC_GUC_TLB_INV_DESC0_VALID);
        let _ = gt.read32(PVC_GUC_TLB_INV_DESC0);
    } else {
        gt.write32(GUC_TLB_INV_CR, GUC_TLB_INV_CR_INVALIDATE);
        let _ = gt.read32(GUC_TLB_INV_CR);
    }
}

/// A GuC of the tile that may cache shared-GGTT translations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GuCTlb {
    /// GT0's GuC.
    Primary,
    /// The standalone media GT's GuC (MTL/Arrow GT1).
    Media,
}

impl GuCTlb {
    pub(crate) const ALL: [Self; 2] = [Self::Primary, Self::Media];
    const fn index(self) -> usize {
        match self {
            Self::Primary => 0,
            Self::Media => 1,
        }
    }
}

/// How one GuC's GGTT TLB is invalidated.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// No GuC may translate through this GGTT: never loaded, or its reset or
    /// stop has been proven.
    Off,
    /// MMIO invalidation on every update. It completes at once.
    Mmio,
    /// CT enabled with submission: CT TLB_INVALIDATION.
    Ct,
}

#[derive(Copy, Clone, Debug)]
struct Client {
    mode: Mode,
    /// Highest generation proven invalidated in this GuC's TLB.
    covered: u64,
}

/// Arena-side bookkeeping. `T` is a removed range retained until every
/// registered GuC has invalidated past the PTE clear that removed it.
pub(crate) struct Tracker<T> {
    generation: u64,
    clients: [Client; 2],
    retained: VecDeque<(u64, T)>,
}

impl<T> core::fmt::Debug for Tracker<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tracker")
            .field("generation", &self.generation)
            .field("clients", &self.clients)
            .field("retained", &self.retained.len())
            .finish()
    }
}

impl<T> Default for Tracker<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Tracker<T> {
    pub(crate) const fn new() -> Self {
        const OFF: Client = Client {
            mode: Mode::Off,
            covered: 0,
        };
        Self {
            generation: 0,
            clients: [OFF; 2],
            retained: VecDeque::new(),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn mode(&self, gt: GuCTlb) -> Mode {
        self.clients[gt.index()].mode
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn retained(&self) -> usize {
        self.retained.len()
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn retained_items(&self) -> impl Iterator<Item = &T> {
        self.retained.iter().map(|(_, item)| item)
    }

    /// One burst of PTE writes is now visible to the GGTT walkers. Returns
    /// the GuCs to invalidate by MMIO now, indexed as [`GuCTlb::ALL`]. An
    /// MMIO-mode GuC catches up only if it was current before this update.
    /// One that still owes a CT-era invalidation stays behind until its
    /// reset is proven.
    pub(crate) fn publish(&mut self) -> [bool; 2] {
        let before = self.generation;
        self.generation += 1;
        let mut mmio = [false; 2];
        for (client, invalidate) in self.clients.iter_mut().zip(mmio.iter_mut()) {
            match client.mode {
                Mode::Off => client.covered = self.generation,
                Mode::Mmio => {
                    *invalidate = true;
                    if client.covered == before {
                        client.covered = self.generation;
                    }
                }
                Mode::Ct => {}
            }
        }
        mmio
    }

    fn threshold(&self) -> u64 {
        self.clients
            .iter()
            .map(|client| client.covered)
            .min()
            .unwrap_or(self.generation)
    }

    /// A range whose PTEs were cleared at `generation`. Return it for release
    /// if every GuC has invalidated past that generation. Otherwise retain it
    /// and return `None`.
    pub(crate) fn remove(&mut self, generation: u64, item: T) -> Option<T> {
        if generation <= self.threshold() {
            return Some(item);
        }
        self.retained.push_back((generation, item));
        None
    }

    /// The generation a CT-mode GuC must invalidate next, if it is behind.
    pub(crate) fn pending(&self, gt: GuCTlb) -> Option<u64> {
        let client = self.clients[gt.index()];
        (client.mode == Mode::Ct && client.covered < self.generation).then_some(self.generation)
    }

    /// A TLB_INVALIDATION sent at `generation` completed on `gt`. Returns
    /// the ranges now releasable.
    pub(crate) fn complete(&mut self, gt: GuCTlb, generation: u64) -> Vec<T> {
        let client = &mut self.clients[gt.index()];
        if generation <= self.generation && generation > client.covered {
            client.covered = generation;
        }
        self.drain()
    }

    /// The GuC's reset was proven (MIA in reset, DMA idle), or a full GT
    /// reset was externally proven. Like xe_tlb_inval_reset this settles
    /// everything owed to it. The GuC then caches nothing and runs no
    /// firmware until an owner boots it again, and that boot invalidates its
    /// TLB by MMIO before the firmware runs. So it also leaves the client set
    /// (`Off`). The arena cannot take forcewake, so it never writes the
    /// registers of a stopped GuC whose wake may already be released.
    pub(crate) fn reset(&mut self, gt: GuCTlb) -> Vec<T> {
        let generation = self.generation;
        let client = &mut self.clients[gt.index()];
        client.covered = generation;
        client.mode = Mode::Off;
        self.drain()
    }

    /// Change one GuC's transport. Registration (from `Off`) happens before
    /// any firmware DMA. Unregistration (to `Off`) happens only after a proven
    /// stop. Neither has stale entries to wait for. Switching between MMIO
    /// and CT keeps any outstanding requirement.
    pub(crate) fn set_mode(&mut self, gt: GuCTlb, mode: Mode) -> Vec<T> {
        let generation = self.generation;
        let client = &mut self.clients[gt.index()];
        if client.mode == Mode::Off || mode == Mode::Off {
            client.covered = generation;
        }
        client.mode = mode;
        self.drain()
    }

    fn drain(&mut self) -> Vec<T> {
        let threshold = self.threshold();
        let mut released = Vec::new();
        while self
            .retained
            .front()
            .is_some_and(|(generation, _)| *generation <= threshold)
        {
            if let Some((_, item)) = self.retained.pop_front() {
                released.push(item);
            }
        }
        released
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Request {
    seqno: u32,
    generation: u64,
    deadline: u64,
}

/// Scheduler-side GGTT invalidation of one GuC over its CT.
#[derive(Debug)]
pub(crate) struct Inval {
    /// xe_tlb_inval.seqno: the next seqno to issue.
    seqno: u32,
    inflight: Option<Request>,
}

const fn next_seqno(seqno: u32) -> u32 {
    let next = (seqno + 1) % SEQNO_MAX;
    if next == 0 {
        1
    } else {
        next
    }
}

impl Inval {
    /// xe_gt_tlb_inval_init_early: seqno 1.
    pub(crate) const fn new() -> Self {
        Self {
            seqno: 1,
            inflight: None,
        }
    }

    pub(crate) fn inflight_seqno(&self) -> Option<u32> {
        self.inflight.map(|request| request.seqno)
    }

    /// The seqno for the next request. Values that are a live per-context
    /// invalidation stamp are skipped, so one 0x7001 cookie never has two
    /// owners.
    pub(crate) fn candidate(&self, live: impl Fn(u32) -> bool) -> u32 {
        let mut seqno = self.seqno;
        for _ in 1..SEQNO_MAX {
            if !live(seqno) {
                break;
            }
            seqno = next_seqno(seqno);
        }
        seqno
    }

    /// The H2G for `seqno` was queued at `now`, covering `generation`.
    pub(crate) fn issued(&mut self, seqno: u32, generation: u64, now: u64) -> Result<(), ()> {
        if self.inflight.is_some() || seqno == 0 || seqno >= SEQNO_MAX {
            return Err(());
        }
        let deadline = now.checked_add(TIMEOUT_NS).ok_or(())?;
        self.inflight = Some(Request {
            seqno,
            generation,
            deadline,
        });
        self.seqno = next_seqno(seqno);
        Ok(())
    }

    /// If `message` is TLB_INVALIDATION_DONE for the in-flight request,
    /// consume it and return the generation it covers.
    pub(crate) fn done(&mut self, message: &GuCMessage) -> Option<u64> {
        let request = self.inflight?;
        if message.kind != 1 || message.auxiliary != DONE || message.payload != [request.seqno] {
            return None;
        }
        self.inflight = None;
        Some(request.generation)
    }

    /// xe_tlb_inval_fence_timeout: the in-flight request is past its bound.
    pub(crate) fn expired(&self, now: u64) -> bool {
        self.inflight.is_some_and(|request| now >= request.deadline)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_ggtt_tlb_tests.rs"]
mod tests;
