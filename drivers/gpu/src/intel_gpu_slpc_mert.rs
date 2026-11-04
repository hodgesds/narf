//! BMG20.01 PF Wa22019338487 + Wa16023588340 lifecycle.
//!
//! MIT Linux b90c984d: xe_gt.c::{xe_gt_enable_host_l2_vram,
//! xe_gt_disable_host_l2_vram}, xe_device.c::{xe_device_l2_flush,
//! xe_device_td_flush}, xe_guc_pc.c::{pc_set_cur_freq,
//! wait_for_act_freq_max_limit,xe_guc_pc_fini_hw}, xe_gt_mcr.c
//! xe2lpg_instance0_steering_table and regs/xe_gt_regs.h.
//! This profile uses GLOBAL_INVAL, not the alternate 2600MHz TDF protocol.
use super::{decode, Limits, SlpcError};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_fence::{CompletionFence, JobError};
use crate::intel_gpu_gem::GemObject;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::Poll;

const BOOT_CAP: u32 = 2133;
const ACTUAL_NS: u64 = 100_000_000;
const MCR_NS: u64 = 50_000_000;
const FLUSH_NS: u64 = 1_000_000;
const SETTLE_NS: u64 = 100_000;

const WRITING: u8 = 0;
const READY: u8 = 1;
const ABANDONED: u8 = 2;

/// Dropping the caller only abandons its response. The GT retains the BO
/// and the completion fence (and its runtime-PM hold) until a fresh flush or
/// the independent post-reset host-L2 shutdown proof.
pub(crate) struct CpuClearLease {
    id: u64,
    state: Arc<AtomicU8>,
    completion: Arc<CompletionFence>,
}
impl CpuClearLease {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
    pub(crate) fn completion(&self) -> Arc<CompletionFence> {
        self.completion.clone()
    }
    pub(crate) fn ready(&self) {
        self.state.store(READY, Ordering::Release);
    }
}
impl Drop for CpuClearLease {
    fn drop(&mut self) {
        let _ =
            self.state
                .compare_exchange(WRITING, ABANDONED, Ordering::AcqRel, Ordering::Acquire);
    }
}
struct RetainedClear {
    object: Arc<GemObject>,
    state: Arc<AtomicU8>,
    completion: Arc<CompletionFence>,
    draining: bool,
}

pub(crate) fn qualified(
    mmio: &impl MmioWindow,
    current: impl FnMut() -> bool,
) -> Result<bool, SlpcError> {
    let mut io = Io::new(mmio, current);
    let a = io.read(0xd8c)?;
    let b = io.read(0xd8c)?;
    if a != b {
        return Err(SlpcError::Unavailable);
    }
    Ok(((a >> 22) & 1023) == 20 && ((a >> 14) & 255) == 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Actual,
    Enable,
    Flush,
    Ready,
    Manual,
    Settle,
    StopActual,
    StopFlush,
    Disable,
    Stopped,
}

/// GuCGt retains this owner, pending clear BO and completion fence with both
/// wake wells through the separate execution-DMA and host-L2 shutdown proofs.
pub(crate) struct Mert {
    epoch: u64,
    limits: Limits,
    stage: Stage,
    deadline: u64,
    settle: u64,
    flush: Option<u64>,
    exposed: bool,
    reset_proven: bool,
    sanitizing: bool,
    next: u64,
    completed: u64,
    pending: Option<(u64, u64)>,
    clear: Option<RetainedClear>,
}
impl Mert {
    pub(crate) fn new(limits: Limits, epoch: u64, now: u64) -> Result<Self, SlpcError> {
        if epoch == 0 || limits.max_mhz > BOOT_CAP || limits.max_mhz > limits.rp0_mhz {
            return Err(SlpcError::State);
        }
        Ok(Self {
            epoch,
            limits,
            stage: Stage::Actual,
            deadline: until(now, ACTUAL_NS)?,
            settle: 0,
            flush: None,
            exposed: false,
            reset_proven: false,
            sanitizing: false,
            next: 1,
            completed: 0,
            pending: None,
            clear: None,
        })
    }
    pub(crate) fn sanitizing(&self) -> bool {
        self.sanitizing
    }
    pub(crate) fn mark_sanitizing(&mut self) {
        self.sanitizing = true;
    }
    pub(crate) fn stopped(&self) -> bool {
        self.stage == Stage::Stopped && !self.exposed
    }
    pub(crate) fn flush_idle(&self) -> bool {
        self.flush.is_none() && self.pending.is_none() && self.clear.is_none()
    }
    pub(crate) fn closing(&mut self) {
        self.reset_proven = false;
    }

    pub(crate) fn prepare(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        epoch: u64,
        current: impl FnMut() -> bool,
    ) -> Poll<Result<(), SlpcError>> {
        if epoch == 0 || epoch != self.epoch {
            return Poll::Ready(Err(SlpcError::State));
        }
        let mut io = Io::new(mmio, current);
        match self.stage {
            Stage::Actual => {
                if decode(io.read(0xc60)? & 511) > BOOT_CAP {
                    if now >= self.deadline {
                        return Poll::Ready(Err(SlpcError::Timeout));
                    }
                } else {
                    self.stage = Stage::Enable;
                    self.deadline = until(now, MCR_NS)?;
                }
            }
            Stage::Enable => match mcr(&mut io, true, &mut self.exposed)? {
                false if now >= self.deadline => return Poll::Ready(Err(SlpcError::Timeout)),
                false => {}
                true => self.stage = Stage::Flush,
            },
            Stage::Flush => {
                if self.poll_flush(&mut io, now)?.is_ready() {
                    self.stage = Stage::Ready;
                    return Poll::Ready(Ok(()));
                }
            }
            Stage::Ready => return Poll::Ready(Ok(())),
            _ => return Poll::Ready(Err(SlpcError::State)),
        }
        Poll::Pending
    }
    pub(crate) fn request_flush(&mut self, epoch: u64, now: u64) -> Result<u64, SlpcError> {
        if epoch == 0 || epoch != self.epoch || self.stage != Stage::Ready || self.reset_proven {
            return Err(SlpcError::State);
        }
        if !self.flush_idle() {
            return Err(SlpcError::Busy);
        }
        let id = self.next;
        self.next = id.checked_add(1).ok_or(SlpcError::Unavailable)?;
        self.pending = Some((id, until(now, MCR_NS)?));
        Ok(id)
    }
    pub(crate) fn retain_cpu_clear(
        &mut self,
        object: Arc<GemObject>,
        epoch: u64,
        now: u64,
    ) -> Result<CpuClearLease, SlpcError> {
        let id = self.request_flush(epoch, now)?;
        let state = Arc::new(AtomicU8::new(WRITING));
        let completion = Arc::new(CompletionFence::new());
        self.clear = Some(RetainedClear {
            object,
            state: state.clone(),
            completion: completion.clone(),
            draining: false,
        });
        Ok(CpuClearLease {
            id,
            state,
            completion,
        })
    }
    pub(crate) fn flush_done(&self, epoch: u64, id: u64) -> Result<bool, SlpcError> {
        if epoch == 0
            || epoch != self.epoch
            || self.stage != Stage::Ready
            || id == 0
            || id >= self.next
        {
            return Err(SlpcError::State);
        }
        Ok(id <= self.completed)
    }
    pub(crate) fn service_flush(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        current: impl FnMut() -> bool,
    ) -> Result<(), SlpcError> {
        let Some((id, mut deadline)) = self.pending else {
            return Ok(());
        };
        if let Some(clear) = &mut self.clear {
            if !clear.draining {
                if clear.state.load(Ordering::Acquire) == WRITING {
                    return Ok(());
                }
                // CPU initialization may span many bounded chunks. Its MCR
                // deadline starts only when writes are finished/abandoned.
                deadline = until(now, MCR_NS)?;
                self.pending = Some((id, deadline));
                clear.draining = true;
            }
        }
        let mut io = Io::new(mmio, current);
        // Loss of either programmed field invalidates the admission proof.
        if self.flush.is_none() && !mcr_verify(&mut io)? {
            return if now >= deadline {
                Err(SlpcError::Timeout)
            } else {
                Ok(())
            };
        }
        match self.poll_flush(&mut io, now) {
            Poll::Pending => {}
            Poll::Ready(result) => {
                result?;
                self.completed = id;
                self.pending = None;
                self.retire_clear(Ok(()));
            }
        }
        Ok(())
    }
    fn poll_flush(
        &mut self,
        io: &mut Io<'_, impl MmioWindow, impl FnMut() -> bool>,
        now: u64,
    ) -> Poll<Result<(), SlpcError>> {
        let value = io.read(0xb404)?;
        if let Some(deadline) = self.flush {
            if value & 1 == 0 {
                self.flush = None;
                return Poll::Ready(Ok(()));
            }
            if now >= deadline {
                return Poll::Ready(Err(SlpcError::Timeout));
            }
        } else {
            // The only global-invalidation client must never consume an
            // unowned request, including one left across reset.
            if value & 1 != 0 {
                return Poll::Ready(Err(SlpcError::Busy));
            }
            let deadline = until(now, FLUSH_NS)?;
            io.write(0xb404, 1)?;
            self.flush = Some(deadline);
        }
        Poll::Pending
    }
    /// Called only after GuC DMA idle and full graphics-engine reset. That
    /// proof retires old execution; it does not prove the host-L2 lease clear.
    pub(crate) fn after_reset(&mut self, now: u64) -> Result<(), SlpcError> {
        if !self.reset_proven {
            self.reset_proven = true;
            self.flush = None;
            self.pending = None;
            self.stage = Stage::Manual;
            self.deadline = until(now, ACTUAL_NS)?;
        }
        Ok(())
    }
    pub(crate) fn finish_stopped(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        current: impl FnMut() -> bool,
    ) -> Poll<Result<(), SlpcError>> {
        if !self.reset_proven {
            return Poll::Ready(Err(SlpcError::State));
        }
        let mut io = Io::new(mmio, current);
        let cap = self.limits.rpe_mhz.min(self.limits.rp0_mhz).min(BOOT_CAP);
        match self.stage {
            Stage::Manual => {
                // GuC is already in reset, so it cannot race software requests.
                io.write(0xa090, 0)?;
                io.write(0xa094, 0)?;
                io.rmw(0xa024, 0x600, 0x400)?;
                let ratio = (cap * 3 + 25) / 50;
                io.rmw(0xa008, 511 << 23, ratio << 23)?;
                self.settle = until(now, SETTLE_NS)?;
                self.stage = Stage::Settle;
            }
            Stage::Settle => {
                if now < self.settle {
                    return Poll::Pending;
                }
                io.rmw(0xa024, 0x600, 0)?;
                self.deadline = until(now, ACTUAL_NS)?;
                self.stage = Stage::StopActual;
            }
            Stage::StopActual => {
                if decode(io.read(0xc60)? & 511) > cap {
                    if now >= self.deadline {
                        return Poll::Ready(Err(SlpcError::Timeout));
                    }
                } else {
                    self.stage = Stage::StopFlush;
                }
            }
            Stage::StopFlush => {
                if self.poll_flush(&mut io, now)?.is_ready() {
                    self.stage = Stage::Disable;
                    self.deadline = until(now, MCR_NS)?;
                }
            }
            Stage::Disable => match mcr(&mut io, false, &mut self.exposed)? {
                false if now >= self.deadline => return Poll::Ready(Err(SlpcError::Timeout)),
                false => {}
                true => {
                    self.stage = Stage::Stopped;
                    self.retire_clear(Err(JobError::Reset));
                    return Poll::Ready(Ok(()));
                }
            },
            Stage::Stopped => return Poll::Ready(Ok(())),
            _ => return Poll::Ready(Err(SlpcError::State)),
        }
        Poll::Pending
    }
    fn retire_clear(&mut self, result: Result<(), JobError>) {
        if let Some(clear) = self.clear.take() {
            // Return the reservation while its independent PM hold is still
            // live; only then wake that hold's terminal-completion waiter.
            drop(clear.object);
            clear.completion.signal(result);
        }
    }
    /// # Safety
    /// The external owner proved full reset plus the manual frequency cap,
    /// fresh global invalidation and host-L2 disable before wake release.
    pub(crate) unsafe fn release_after_reset(mut self) {
        self.retire_clear(Err(JobError::Reset));
    }
}
fn until(now: u64, duration: u64) -> Result<u64, SlpcError> {
    now.checked_add(duration).ok_or(SlpcError::Timeout)
}

/// Every target *and wake-proof* access rechecks current PCI D0/authority.
/// Loss is sticky, including cleanup: no write derives from an all-ones read.
struct Io<'a, M, F> {
    mmio: &'a M,
    current: F,
    lost: bool,
}
impl<'a, M: MmioWindow, F: FnMut() -> bool> Io<'a, M, F> {
    fn new(mmio: &'a M, current: F) -> Self {
        Self {
            mmio,
            current,
            lost: false,
        }
    }
    fn raw(&mut self, reg: u64) -> Result<u32, SlpcError> {
        if self.lost || !(self.current)() {
            self.lost = true;
            return Err(SlpcError::Unavailable);
        }
        let value = self.mmio.read32(reg);
        if value == u32::MAX {
            self.lost = true;
            return Err(SlpcError::Unavailable);
        }
        Ok(value)
    }
    fn awake(&mut self) -> Result<(), SlpcError> {
        for reg in [0xa188, 0xdfc, 0xa278, 0xd84] {
            if self.raw(reg)? & 1 == 0 {
                self.lost = true;
                return Err(SlpcError::Unavailable);
            }
        }
        Ok(())
    }
    fn read(&mut self, reg: u64) -> Result<u32, SlpcError> {
        self.awake()?;
        self.raw(reg)
    }
    fn write(&mut self, reg: u64, value: u32) -> Result<(), SlpcError> {
        self.awake()?;
        if !(self.current)() {
            self.lost = true;
            return Err(SlpcError::Unavailable);
        }
        self.mmio.write32(reg, value);
        Ok(())
    }
    fn rmw(&mut self, reg: u64, mask: u32, set: u32) -> Result<(), SlpcError> {
        let old = self.read(reg)?;
        self.write(reg, (old & !mask) | set)?;
        if self.read(reg)? & mask != set {
            return Err(SlpcError::Unavailable);
        }
        Ok(())
    }
}
fn steering<M: MmioWindow, F: FnMut() -> bool>(
    io: &mut Io<'_, M, F>,
    operation: impl FnOnce(&mut Io<'_, M, F>) -> Result<(), SlpcError>,
) -> Result<bool, SlpcError> {
    if io.read(0xfd0)? & 1 == 0 {
        return Ok(false);
    }
    let saved = io.read(0xfd4)?;
    // Source xe2lpg_instance0 table covers both GAMREQSTRM and L3CLOS.
    let result = (|| {
        io.write(0xfd4, (saved & !0x80000f0f) | 0x80000000)?;
        if io.read(0xfd4)? != ((saved & !0x80000f0f) | 0x80000000) {
            return Err(SlpcError::Unavailable);
        }
        operation(io)
    })();
    let restore = io.write(0xfd4, saved).and_then(|()| {
        if io.read(0xfd4)? != saved {
            return Err(SlpcError::Unavailable);
        }
        io.write(0xfd0, 1)
    });
    result.and(restore).map(|()| true)
}
fn mcr(
    io: &mut Io<'_, impl MmioWindow, impl FnMut() -> bool>,
    enable: bool,
    exposed: &mut bool,
) -> Result<bool, SlpcError> {
    let completed = steering(io, |io| {
        if enable {
            *exposed = true;
        }
        io.rmw(0x4194, 64, if enable { 64 } else { 0 })?;
        if enable {
            // xe_gt_enable_host_l2_vram defines the whole CLOS3 way mask,
            // not an unrelated-field RMW: every other way must be disabled.
            io.write(0xb1ac, 0xf)?;
            if io.read(0xb1ac)? != 0xf {
                return Err(SlpcError::Unavailable);
            }
        }
        Ok(())
    })?;
    if completed && !enable {
        *exposed = false;
    }
    Ok(completed)
}
fn mcr_verify(io: &mut Io<'_, impl MmioWindow, impl FnMut() -> bool>) -> Result<bool, SlpcError> {
    steering(io, |io| {
        if io.read(0x4194)? & 64 == 0 || io.read(0xb1ac)? != 0xf {
            return Err(SlpcError::Unavailable);
        }
        Ok(())
    })
}
