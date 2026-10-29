//! One graphics-GT owner for forcewake, GuC bootstrap and CT memory.
//!
//! Reference: ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! MIT xe_force_wake.c and regs/xe_gt_regs.h, plus xe_guc.c reset protocol.
//! This owner is exclusive, not a refcount shared with the legacy Gen12
//! forcewake manager. The PCI owner supplies runtime-PM and serializes all
//! other reset/firmware users. No userspace submission is admitted here.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_guc::GuCMessage;
use crate::intel_gpu_guc_boot::{BootAllocator, BootConfig, BootError, BootState, GuCBoot};
use crate::intel_gpu_guc_firmware::GuCFirmware;
use crate::intel_gpu_guc_transport::{TransportError, TransportState, XeLpgTransport};
use core::mem::ManuallyDrop;
use core::task::Poll;

const REQUEST: u64 = 0xa188;
const WAKE_NS: u64 = 50_000_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GtState {
    Staged,
    Waking,
    Booting,
    Ready,
    EnablingCt,
    CtReady,
    Recovering,
    Stopping,
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
}

struct Parts<M: MmioWindow, A: BootAllocator> {
    boot: GuCBoot<M, A>,
    ct: Option<XeLpgTransport<M, A>>,
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

    pub(crate) fn from_staged(boot: GuCBoot<M, A>) -> Self {
        assert_eq!(boot.state(), BootState::Staged);
        Self {
            parts: ManuallyDrop::new(Parts { boot, ct: None }),
            state: GtState::Staged,
            deadline: 0,
            requested: false,
            released: false,
        }
    }

    pub fn state(&self) -> GtState {
        self.state
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
        Ok(())
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
                | GtState::Stopping
                | GtState::Releasing
        ) {
            return Err(GtError::State);
        }
        // Close admission before any fallible reset/recovery operation.
        self.state = GtState::Lost;
        if matches!(
            self.parts.boot.state(),
            BootState::Staged | BootState::Stopped
        ) {
            self.request(false, now)?;
            self.state = GtState::Releasing;
            return Ok(());
        }
        match self.awake() {
            Ok(()) => return self.start_reset(now),
            Err(GtError::WakeLost) => {}
            Err(error) => return Err(error),
        }
        // No DMA memory is reclaimed while recovering a dropped wake ACK.
        self.request(true, now)?;
        self.state = GtState::Recovering;
        Ok(())
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
                    self.start_reset(now)?;
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
            GtState::Booting => match self.parts.boot.poll(now) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(GtError::Boot(error))),
                Poll::Ready(Ok(BootState::Ready)) => self.state = GtState::Ready,
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
                    Poll::Ready(Ok(TransportState::Enabled)) => self.state = GtState::CtReady,
                    _ => return Poll::Ready(Err(GtError::State)),
                }
            }
            GtState::Stopping => match self.parts.boot.poll(now) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(GtError::Boot(error))),
                Poll::Ready(Ok(BootState::Stopped)) => {
                    if let Some(ct) = self.parts.ct.take() {
                        // SAFETY: this owner is the sole CT publisher. GuCBoot
                        // proved MIA in reset and firmware DMA idle. No child
                        // escapes this owner, and the terminal GT cannot
                        // re-enable CT or run stale registrations afterwards.
                        unsafe { ct.release_after_reset() };
                    }
                    self.request(false, now)?;
                    self.state = GtState::Releasing;
                    return Poll::Pending;
                }
                _ => return Poll::Ready(Err(GtError::State)),
            },
            GtState::Ready | GtState::CtReady => {}
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
    /// The PCI owner proved a full GT reset stopped all GuC/firmware DMA,
    /// invalidated stale addresses and released/reset the kernel wake request.
    /// Neither unreadable registers nor elapsed time supplies that proof.
    pub unsafe fn release_after_gt_reset(mut self) {
        self.released = true;
        // SAFETY: consumed once under the caller's full-reset proof.
        let Parts { boot, ct } = unsafe { ManuallyDrop::take(&mut self.parts) };
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
