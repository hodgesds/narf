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
use crate::intel_gpu_pipes::{Pipe, PLANE_OFFSET_OFFSET, PLANE_PRIMARY_OFFSET, PLANE_SURF_OFFSET};
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
    /// Stable physical PCI BAR identity; isolated native register vectors may
    /// omit it, but production DMA reservations always supply the shared key.
    fn ggtt_key(&self) -> Option<u64> {
        None
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum IoError {
    Unsupported,
    Bounds,
    Conflict,
    Unavailable,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct SavedStatus {
    ier: u32,
    imr: u32,
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
    generation: Generation,
    status: u32,
    saved_ier: u32,
    saved_imr: u32,
    state: Cell<State>,
    last_pte: Cell<Option<(u64, u32)>>,
    /// Exact original linear console layout, supplied from the retained
    /// source-qualified KMS owner; reset never samples a new baseline.
    console_layout: Option<(u32, u32)>,
    xr30_qualified: Cell<bool>,
    primary_controls: Cell<Option<(u32, Option<u32>)>>,
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
            Generation::LunarLake | Generation::PantherLake => return Err(IoError::Unsupported),
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
        if let Some(key) = mmio.ggtt_key() {
            let ledger = crate::intel_gpu_ggtt_ranges::Ledger::for_bar(key, bar_len)
                .map_err(|_| IoError::Bounds)?;
            if !ledger.allows(
                crate::intel_gpu_ggtt_ranges::Kind::Primary,
                GEM_SCANOUT_GTT_START,
                GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START,
            ) {
                return Err(IoError::Bounds);
            }
        }

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
            generation,
            status,
            saved_ier: 0,
            saved_imr: 0,
            state: Cell::new(State::Initializing),
            last_pte: Cell::new(None),
            console_layout: None,
            xr30_qualified: Cell::new(false),
            primary_controls: Cell::new(None),
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

    /// Bind CPU console restoration before Presenter exposure. This grants
    /// only the retained source-selected original CTL and pitch; client view
    /// updates still require the owned DSB and a fresh final SURF latch.
    pub(crate) fn qualify_console(
        &mut self,
        family: Option<crate::intel_gpu_gt::Gen12Platform>,
        control: u32,
        stride: u32,
    ) -> Result<(), IoError> {
        let expected = match (self.format, family) {
            (PteFormat::Gen12, Some(family)) => {
                if (self.generation == Generation::TigerLake)
                    != (family == crate::intel_gpu_gt::Gen12Platform::TigerLake)
                {
                    return Err(IoError::Unsupported);
                }
                if stride > crate::intel_gpu_scanout::gen12_max_stride(family) / 64 {
                    return Err(IoError::Unsupported);
                }
                crate::intel_gpu_pipes::gen12_xrgb_control(family)
            }
            (PteFormat::XeLpg, None) => 0x84000000,
            _ => return Err(IoError::Unsupported),
        };
        // Preserve already-admitted MTL's original harmless trickle/clear
        // controls. Format and arbitration stay source-exact; Gen12's
        // stronger primary owner admits only the exact family literal.
        let harmless = if self.format == PteFormat::XeLpg {
            (1 << 14) | (1 << 13)
        } else {
            0
        };
        if self.state.get() != State::Active
            || stride == 0
            || stride > 0xfff
            || control & !harmless != expected
        {
            return Err(IoError::Unsupported);
        }
        if self
            .console_layout
            .is_some_and(|old| old != (control, stride))
        {
            return Err(IoError::Conflict);
        }
        self.console_layout = Some((control, stride));
        Ok(())
    }

    /// The KMS owner has verified the exact physical display14 fixed resource
    /// and timing profile. This never reinterprets a readable XR30 as ownership.
    pub(crate) fn qualify_xr30(&self) -> Result<(), IoError> {
        if self.format != PteFormat::XeLpg
            || self.generation != Generation::MeteorLake
            || self.console_layout.is_none()
        {
            return Err(IoError::Unsupported);
        }
        self.owned_status_ready()?;
        self.xr30_qualified.set(true);
        Ok(())
    }

    pub(crate) fn format(&self) -> PteFormat {
        self.format
    }

    pub(crate) fn saved_status(&self) -> SavedStatus {
        SavedStatus {
            ier: self.saved_ier,
            imr: self.saved_imr,
        }
    }

    pub(crate) fn snapshot_status(
        mmio: &M,
        generation: Generation,
    ) -> Result<SavedStatus, IoError> {
        if !mmio.access_ok() {
            return Err(IoError::Unavailable);
        }
        let ier = mmio.read32(IER);
        let imr = mmio.read32(IMR);
        if ier == u32::MAX || !mmio.access_ok() {
            return Err(IoError::Unavailable);
        }
        let status = COMMON_STATUS
            | if generation == Generation::MeteorLake {
                MTL_ATS_STATUS
            } else {
                0
            };
        Ok(SavedStatus {
            ier: ier & status,
            imr: imr & status,
        })
    }

    /// Acquire a new status observation after reset while preserving the
    /// original firmware ownership, rather than treating our old IER/IMR
    /// bits as inherited state. The old adapter remains permanently lost.
    ///
    /// # Safety
    /// Same exclusion/current cache-policy requirements as `new`. Old DMA
    /// owners remain retained; this acquisition is no fetch-stop proof.
    pub(crate) unsafe fn after_reset(
        mmio: M,
        generation: Generation,
        pipe: Pipe,
        bar_len: u64,
        saved: SavedStatus,
    ) -> Result<Self, IoError> {
        // SAFETY: caller supplies the constructor's current ownership proof.
        let mut owner = unsafe { Self::new(mmio, generation, pipe, bar_len) }?;
        owner.saved_ier = saved.ier;
        owner.saved_imr = saved.imr;
        Ok(owner)
    }

    pub(crate) fn poison(&self) {
        self.state.set(State::Lost);
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
        // Only the original console's zero source origin may be restored
        // through CPU IO. Client panning is emitted by the owned DSB in its
        // hardware safe window, never through this register adapter.
        let console_origin =
            offset == Pipe::A.base() + PLANE_PRIMARY_OFFSET + PLANE_OFFSET_OFFSET && value == 0;
        // Only enabled linear XRGB may be restored by this adapter. Client
        // tiling/stride changes use DSB. The Presenter retains the exact
        // original CTL/pitch and later proves the console's SURF latch.
        let console_layout = self.console_layout.is_some_and(|(control, stride)| {
            if !matches!(offset, 0x70180 | 0x70188) {
                return false;
            }
            let current_control = self.read32(0x70180);
            let current_stride = self.read32(0x70188);
            let tiling = current_control & (7 << 10);
            let layout_owned = (current_control & !(7 << 10) == control
                && (tiling == 0
                    || tiling == 1 << 10
                    || (self.format == PteFormat::XeLpg && tiling == 5 << 10)))
                || (self.supports_xr30() && self.retained_primary_control(current_control));
            let pitch_owned = current_stride == stride
                || (stride % 8 == 0 && current_stride == stride / 8)
                || (self.format == PteFormat::XeLpg
                    && stride % 2 == 0
                    && current_stride == stride / 2);
            layout_owned && pitch_owned && value == if offset == 0x70180 { control } else { stride }
        });
        if self.state.get() != State::Active
            || !(pte || offset == surface || offset == IIR || console_origin || console_layout)
            || ((console_origin || console_layout) && self.owned_status_ready().is_err())
        {
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
    fn supports_xr30(&self) -> bool {
        self.xr30_qualified.get()
            && self.format == PteFormat::XeLpg
            && self.owned_status_ready().is_ok()
    }
    fn retain_primary_controls(&self, original: u32, current: u32, pending: Option<u32>) -> bool {
        let Some((console, _)) = self.console_layout else {
            return false;
        };
        let legal = |control: u32| {
            let rest = control & !((0x1f << 23) | (7 << 10));
            let format = control & (0x1f << 23);
            let tiling = control & (7 << 10);
            rest == console & !((0x1f << 23) | (7 << 10))
                && ((format == 0x04000000 && matches!(tiling, 0 | 0x400 | 0x1400))
                    || (format == 0x02000000 && tiling == 0))
        };
        if !self.supports_xr30()
            || original != console
            || !legal(current)
            || pending.is_some_and(|control| !legal(control))
        {
            return false;
        }
        self.primary_controls.set(Some((current, pending)));
        true
    }
    fn retained_primary_control(&self, control: u32) -> bool {
        self.supports_xr30()
            && self
                .primary_controls
                .get()
                .is_some_and(|(old, pending)| control == old || pending == Some(control))
    }
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
