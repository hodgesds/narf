//! Production display-only GGTT posting and poll-only primary-plane status.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! i915/gt/intel_ggtt.c::{needs_wc_ggtt_mapping,gen8_ggtt_invalidate},
//! i915/display/intel_display_irq.c::gen8_de_irq_postinstall and
//! intel_display_regs.h::GEN8_DE_PIPE_{IIR,IMR,IER}.
//!
//! Gen11+ GGTT PTE mappings must be UC: WC bursts can drop PTE writes.
//! The display-only UC path needs posting/order, not a fabricated flush-bit
//! self-clear wait. GuC/engine translation caches require their separate GT
//! invalidation protocol; this reserved arena must never be named by them.

use core::cell::Cell;
use core::sync::atomic::{compiler_fence, fence, Ordering};

use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gtt::{
    check_ggtt_range, PteFormat, GEM_SCANOUT_GTT_END, GEM_SCANOUT_GTT_START, GGTT_ARRAY_BASE,
};
use crate::intel_gpu_pipes::{Pipe, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET};
use crate::intel_gpu_scanout::ScanoutIo;

const IMR: u64 = 0x44404;
const IIR: u64 = 0x44408;
const IER: u64 = 0x4440c;
const FLIP_DONE: u32 = 1 << 3;
const COMMON_STATUS: u32 = FLIP_DONE | (1 << 7) | (1 << 25) | (1 << 31);
const MTL_ATS_STATUS: u32 = (1 << 18) | (1 << 24);
const FRAME_COUNT: u64 = 0x40;

/// Current PCI capability invocation plus retained D0/display-well ownership.
///
/// # Safety
/// Every forwarded MMIO access must check current authority, not just a prior
/// grant. A refused access returns all-ones for reads and performs no writes.
/// The owner retains the UC BAR mapping, this PCI function's power and the
/// active pipe's display wells, excludes modeset/PSR/suspend/reset and prevents
/// another consumer from clearing this pipe's owned IIR status. `access_ok`
/// must become false when that ownership or its reset generation is lost.
/// Calling this predicate must neither wait nor re-enter the presenter.
pub(crate) unsafe trait DisplayAccess: MmioWindow {
    fn access_ok(&self) -> bool;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum IoError {
    Unsupported,
    Bounds,
    Conflict,
    Unavailable,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum State {
    Initializing,
    Active,
    Restored,
    Lost,
}

/// One pipe-A internal-panel status owner. Use inside the per-card service's
/// mutex; there is no interrupt handler and no independent MMIO polling loop.
/// Drop performs no hardware operations; uncertain Presenter destruction
/// retains this adapter together with the owned mappings and system pages.
pub(crate) struct PollIo<M: DisplayAccess> {
    mmio: M,
    bar_len: u64,
    format: PteFormat,
    status: u32,
    saved_ier: u32,
    saved_imr: u32,
    state: Cell<State>,
    last_pte: Cell<Option<(u64, u32)>>,
}

impl<M: DisplayAccess> core::fmt::Debug for PollIo<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PollIo")
            .field("format", &self.format)
            .field("active", &(self.state.get() == State::Active))
            .finish_non_exhaustive()
    }
}

impl<M: DisplayAccess> PollIo<M> {
    /// Acquire latching while leaving delivery masked, preserving every
    /// unrelated IER/IMR/IIR bit. No pending fault is silently acknowledged.
    ///
    /// # Safety
    /// Caller has matched the actual PCI function to `generation`, owns an
    /// already-running pipe-A internal panel and its primary plane, and has
    /// excluded every other user of the GEM GGTT arena. Initial PTEs are clear
    /// and posted. Neither GuC, GT batches nor other display fetchers may name
    /// this arena, including between surface release and address reuse.
    /// The mapping is UC, not WC. Caller supplies Presenter's generation PTE
    /// format/cache index; on Xe-LPG its PAT entry must already be verified
    /// under live GT ownership. This constructor never programs a PAT table.
    pub(crate) unsafe fn new(
        mmio: M,
        generation: Generation,
        pipe: Pipe,
        bar_len: u64,
    ) -> Result<Self, IoError> {
        let format = match generation {
            Generation::TigerLake | Generation::AlderLake => PteFormat::Gen12,
            Generation::MeteorLake => PteFormat::XeLpg,
            Generation::PantherLake => return Err(IoError::Unsupported),
        };
        if pipe != Pipe::A {
            return Err(IoError::Unsupported);
        }
        check_ggtt_range(
            bar_len,
            GEM_SCANOUT_GTT_START,
            GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START,
        )
        .map_err(|_| IoError::Bounds)?;
        let status = COMMON_STATUS
            | if format == PteFormat::XeLpg {
                MTL_ATS_STATUS
            } else {
                0
            };
        let mut owner = Self {
            mmio,
            bar_len,
            format,
            status,
            saved_ier: 0,
            saved_imr: 0,
            state: Cell::new(State::Initializing),
            last_pte: Cell::new(None),
        };
        owner.present()?;
        let ier = owner.checked_read(IER)?;
        // All-ones IMR is a valid fully masked value. Availability comes from
        // current authority and the readable pipe/frame/IER observations.
        let imr = owner.raw_read(IMR)?;
        let iir = owner.checked_read(IIR)?;
        if ier & !imr & status != 0 || iir & (status & !FLIP_DONE) != 0 {
            return Err(IoError::Conflict);
        }
        owner.saved_ier = ier & status;
        owner.saved_imr = imr & status;
        owner.write_checked(IMR, imr | status)?;
        if owner.raw_read(IMR)? & status != status {
            return owner.fail();
        }
        owner.write_checked(IER, ier | status)?;
        if owner.checked_read(IER)? & status != status {
            return owner.fail();
        }
        // The source IIR can retain two queued indications. Drain only the
        // owned flip-done bit, twice, with delivery still masked.
        for _ in 0..2 {
            owner.write_checked(IIR, FLIP_DONE)?;
            let _ = owner.checked_read(IIR)?;
        }
        if owner.checked_read(IIR)? & FLIP_DONE != 0 {
            return owner.fail();
        }
        owner.present()?;
        owner.state.set(State::Active);
        Ok(owner)
    }

    pub(crate) fn format(&self) -> PteFormat {
        self.format
    }

    fn fail<T>(&self) -> Result<T, IoError> {
        self.state.set(State::Lost);
        Err(IoError::Unavailable)
    }
    fn available(&self, offset: u64) -> bool {
        if self.state.get() == State::Lost
            || self.state.get() == State::Restored
            || offset % 4 != 0
            || offset.checked_add(4).is_none_or(|end| end > self.bar_len)
            || !self.mmio.access_ok()
        {
            self.state.set(State::Lost);
            false
        } else {
            true
        }
    }
    fn raw_read(&self, offset: u64) -> Result<u32, IoError> {
        if !self.available(offset) {
            return Err(IoError::Unavailable);
        }
        let value = self.mmio.read32(offset);
        if !self.mmio.access_ok() {
            return self.fail();
        }
        Ok(value)
    }
    fn checked_read(&self, offset: u64) -> Result<u32, IoError> {
        let value = self.raw_read(offset)?;
        if value == u32::MAX {
            self.fail()
        } else {
            Ok(value)
        }
    }
    fn write_checked(&self, offset: u64, value: u32) -> Result<(), IoError> {
        if !self.available(offset) {
            return Err(IoError::Unavailable);
        }
        self.mmio.write32(offset, value);
        if !self.mmio.access_ok() {
            self.fail()
        } else {
            Ok(())
        }
    }
    fn present(&self) -> Result<(), IoError> {
        // A frame counter wrapping through all-ones is conservatively
        // refused; elapsed time never establishes power.
        let frame = self.raw_read(Pipe::A.base() + FRAME_COUNT)?;
        if frame == u32::MAX {
            return self.fail();
        }
        Ok(())
    }
    fn owned_status_ready(&self) -> Result<(), IoError> {
        if self.state.get() != State::Active {
            return self.fail();
        }
        self.present()?;
        if self.checked_read(IER)? & self.status != self.status
            || self.raw_read(IMR)? & self.status != self.status
        {
            return self.fail();
        }
        Ok(())
    }

    /// Release status ownership after every owned GEM mapping is independently
    /// proven no longer fetched. The inherited console may remain running.
    ///
    /// # Safety
    /// No pending or current GEM surface is fetched by this pipe or any other
    /// engine. Power/current authority and mode/reset exclusion remain held.
    /// A stale SURFLIVE sample, a timeout or a PLANE_CTL request is not proof.
    pub(crate) unsafe fn restore_stopped(&self) -> bool {
        if self.state.get() == State::Restored {
            return true;
        }
        if self.owned_status_ready().is_err() {
            return false;
        }
        let restore = || -> Result<(), IoError> {
            // Keep delivery masked until the original IER ownership is back.
            let ier = self.checked_read(IER)?;
            self.write_checked(IER, (ier & !self.status) | self.saved_ier)?;
            if self.checked_read(IER)? & self.status != self.saved_ier {
                return self.fail();
            }
            for _ in 0..2 {
                self.write_checked(IIR, FLIP_DONE)?;
                let _ = self.checked_read(IIR)?;
            }
            let imr = self.raw_read(IMR)?;
            self.write_checked(IMR, (imr & !self.status) | self.saved_imr)?;
            if self.raw_read(IMR)? & self.status != self.saved_imr {
                return self.fail();
            }
            self.present()?;
            Ok(())
        };
        if restore().is_err() {
            return false;
        }
        self.state.set(State::Restored);
        true
    }
}

impl<M: DisplayAccess> MmioWindow for PollIo<M> {
    fn read32(&self, offset: u64) -> u32 {
        if offset == IIR && self.owned_status_ready().is_err() {
            return u32::MAX;
        }
        self.raw_read(offset).unwrap_or(u32::MAX)
    }
    fn write32(&self, offset: u64, value: u32) {
        let pte_start = GGTT_ARRAY_BASE + GEM_SCANOUT_GTT_START / 4096 * 8;
        let pte_end = GGTT_ARRAY_BASE + GEM_SCANOUT_GTT_END / 4096 * 8;
        let pte = (pte_start..pte_end).contains(&offset);
        let surface = Pipe::A.base() + PLANE_PRIMARY_OFFSET + PLANE_SURF_OFFSET;
        if self.state.get() != State::Active || !(pte || offset == surface || offset == IIR) {
            self.state.set(State::Lost);
            return;
        }
        if offset == IIR && (value != FLIP_DONE || self.owned_status_ready().is_err()) {
            self.state.set(State::Lost);
            return;
        }
        if self.write_checked(offset, value).is_ok() && pte {
            self.last_pte.set(Some((offset, value)));
        }
    }
}

// SAFETY: constructor establishes exact profile and exclusive status/arena
// ownership. DisplayAccess retains current authority, UC mapping and power.
// The documented display-only UC GGTT protocol has no stale engine/GuC TLB
// because the arena is unreachable by those clients; posted reads plus the
// hardware barrier order PTE writes before plane arm and address reuse.
unsafe impl<M: DisplayAccess> ScanoutIo for PollIo<M> {
    fn invalidate_ggtt(&self) -> bool {
        if self.owned_status_ready().is_err() {
            return false;
        }
        compiler_fence(Ordering::SeqCst);
        fence(Ordering::SeqCst);
        if let Some((offset, expected)) = self.last_pte.get() {
            if self.raw_read(offset) != Ok(expected) {
                self.state.set(State::Lost);
                return false;
            }
        }
        let ok = self.owned_status_ready().is_ok();
        compiler_fence(Ordering::SeqCst);
        ok
    }

    unsafe fn finish_stopped(&self) -> bool {
        // SAFETY: the trait caller supplies the same no-owned-GEM-fetch proof.
        unsafe { self.restore_stopped() }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_scanout_io_tests.rs"]
mod tests;
