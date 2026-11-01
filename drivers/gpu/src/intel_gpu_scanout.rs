//! Owned linear GEM scanout windows and primary-surface latch tracking.
//!
//! References: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! xe/display/xe_fb_pin.c, i915/display/{skl_universal_plane_regs.h,
//! intel_display_regs.h,intel_display_irq.c}. A PLANE_SURF write is an arm,
//! not completion: the previous buffer survives until fresh flip-done,
//! SURFLIVE and a stable changed hardware frame counter agree.
//!
//! This owner is deliberately not installed by the KMS copy path yet. Its
//! caller must own display power, console handoff, modeset/PM exclusion and
//! event publication. The current generic KMS path does not provide those
//! contracts. No display IRQ enable/mask or synthetic vblank is changed here.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gem::GemObject;
use crate::intel_gpu_gtt::{
    check_ggtt_range, PteFormat, GEM_SCANOUT_GTT_END, GEM_SCANOUT_GTT_START, GGTT_ARRAY_BASE,
    GTT_PAGE_SIZE,
};
use crate::intel_gpu_pipes::{
    Pipe, PLANE_CTL_ENABLE, PLANE_CTL_OFFSET, PLANE_OFFSET_OFFSET, PLANE_PRIMARY_OFFSET,
    PLANE_SIZE_OFFSET, PLANE_STRIDE_OFFSET, PLANE_SURF_OFFSET,
};

const SURFLIVE_OFFSET: u64 = 0x2c;
const FRAMECOUNT_OFFSET: u64 = 0x40;
const PIPE_IIR_BASE: u64 = 0x44408;
const PRIMARY_FLIP_DONE: u32 = 1 << 3;
const PLANE_FAULT: u32 = 1 << 7;
const FIFO_UNDERRUN: u32 = 1 << 31;
const CTL_FORMAT_MASK: u32 = 0x1f << 23;
const CTL_TILED_MASK: u32 = 7 << 10;
const CTL_RGB_ORDER: u32 = 1 << 20;
const CTL_XRGB8888: u32 = 8 << 23;
// ICL+ arbitration slots and the harmless trickle-feed/clear-color disable
// controls may be inherited. All auxiliary/YUV/keying, compression, async,
// horizontal-flip and rotation bits must be clear for this linear surface.
const ALLOWED_CTL: u32 = PLANE_CTL_ENABLE | (7 << 28) | CTL_FORMAT_MASK | (1 << 14) | (1 << 13);
const AUX_DIST_OFFSET: u64 = 0x40;
const AUX_OFFSET_OFFSET: u64 = 0x44;
const CUS_CTL_OFFSET: u64 = 0x48;
const COLOR_CTL_OFFSET: u64 = 0x4c;
const FLIP_TIMEOUT_NS: u64 = 1_000_000_000;

/// MMIO and GGTT invalidation retained for as long as any scanout may fetch.
///
/// # Safety
/// The implementation retains this PCI function's power/wake and current
/// access authority. `invalidate_ggtt` returns true only after *verified*
/// invalidation of every relevant GGTT translation cache, including after
/// clearing mappings. A refused/revoked access must fail, never look like
/// successful zero-valued MMIO. It must not re-enter this presenter.
pub unsafe trait ScanoutIo: MmioWindow {
    fn invalidate_ggtt(&self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SurfaceId(u64);

/// A zero-offset LINEAR XRGB8888 source. Surface-only flips retain the
/// existing timing, watermark, stride, format and primary-plane geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
}
impl Geometry {
    fn extent(self) -> Result<u64, ScanoutError> {
        let bytes = u64::from(self.pitch) * u64::from(self.height);
        if self.width == 0
            || self.height == 0
            || self.width > 8192
            || self.height > 8192
            || self.pitch % 64 != 0
            || self.pitch < self.width * 4
            // Direct PLANE_STRIDE is only 12 bits in 64-byte units. The
            // framebuffer ioctl's 256 KiB remapped limit is not encodable
            // here: this presenter never remaps the source geometry.
            || self.pitch / 64 > 0xfff
            || (self.pitch > 128 * 1024 && self.pitch % 4096 != 0)
            || bytes > GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START
        {
            return Err(ScanoutError::Unsupported);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanoutError {
    Unsupported,
    Bounds,
    Busy,
    UnknownSurface,
    Unavailable,
    Timeout,
}

struct Surface {
    object: Arc<GemObject>,
    offset: u32,
    pages: u32,
    geometry: Geometry,
}
#[derive(Clone, Copy)]
struct Pending {
    id: SurfaceId,
    ticket: u64,
    frame: u32,
    deadline: u64,
}

/// Hardware evidence for this particular armed surface. `stamp.ns` is the
/// observation time, not an inferred time of the vblank edge or an IRQ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub surface: SurfaceId,
    pub ticket: u64,
    pub stamp: crate::drm::card::FlipStamp,
    /// Safe to release now; it remains owned until `release` succeeds.
    pub retired: Option<SurfaceId>,
}

/// Exclusive owner of one pipe's primary surface and a function-wide GGTT
/// arena. Keep one owner for this PCI function; additional pipes need to
/// share its allocator rather than construct overlapping owners.
pub struct Presenter<M: ScanoutIo> {
    io: Option<M>,
    pipe: Pipe,
    format: PteFormat,
    pat: u8,
    free: Vec<(u32, u32)>,
    surfaces: BTreeMap<SurfaceId, Surface>,
    next_id: u64,
    current: Option<SurfaceId>,
    expected_surface: u32,
    pending: Option<Pending>,
    failed: bool,
    closed: bool,
}

impl<M: ScanoutIo> core::fmt::Debug for Presenter<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Presenter")
            .field("pipe", &self.pipe)
            .field("surfaces", &self.surfaces.len())
            .field("current", &self.current)
            .field("pending", &self.pending.map(|pending| pending.id))
            .field("failed", &self.failed)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl<M: ScanoutIo> Presenter<M> {
    /// Acquire the reserved 160..256 MiB window and an already-running plane.
    /// No writes occur here. `initial_surface` belongs to the caller until
    /// the first successful latch retires it; this owner never frees it.
    ///
    /// # Safety
    /// Caller exclusively owns this function's GEM scanout arena and this
    /// plane (including its flip-done status and no outstanding flip); no
    /// firmware, GT batch, other pipe or owner can name these new mappings.
    /// All initial arena entries
    /// are invalid and caches invalidated. The supplied PTE format/cache
    /// index is programmed for this generation and WC system scanout. Caller
    /// retains the original surface and prevents console writes, PSR entry,
    /// modesets, suspend/reset and power removal for this owner's lifetime.
    /// Drop without successful `shutdown_stopped` quarantines its resources.
    pub unsafe fn new(
        io: M,
        bar_len: u64,
        pipe: Pipe,
        format: PteFormat,
        pat: u8,
        initial_surface: u32,
    ) -> Result<Self, ScanoutError> {
        check_ggtt_range(
            bar_len,
            GEM_SCANOUT_GTT_START,
            GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START,
        )
        .map_err(|_| ScanoutError::Bounds)?;
        format
            .encode_ggtt(0, pat)
            .map_err(|_| ScanoutError::Unsupported)?;
        if initial_surface % 4096 != 0
            || (GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(initial_surface))
        {
            return Err(ScanoutError::Bounds);
        }
        let owner = Self {
            io: Some(io),
            pipe,
            format,
            pat,
            free: alloc::vec![(
                GEM_SCANOUT_GTT_START as u32,
                ((GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START) / GTT_PAGE_SIZE) as u32,
            )],
            surfaces: BTreeMap::new(),
            next_id: 1,
            current: None,
            expected_surface: initial_surface,
            pending: None,
            failed: false,
            closed: false,
        };
        if owner.io().read32(owner.plane() + PLANE_SURF_OFFSET) != initial_surface
            || owner.io().read32(owner.plane() + SURFLIVE_OFFSET) != initial_surface
        {
            return Err(ScanoutError::Unavailable);
        }
        Ok(owner)
    }

    fn io(&self) -> &M {
        self.io.as_ref().expect("scanout owner")
    }
    fn plane(&self) -> u64 {
        self.pipe.base() + PLANE_PRIMARY_OFFSET
    }
    fn iir(&self) -> u64 {
        PIPE_IIR_BASE + self.pipe as u64 * 0x10
    }
    fn ready(&self) -> Result<(), ScanoutError> {
        if self.failed || self.closed {
            Err(ScanoutError::Unavailable)
        } else {
            Ok(())
        }
    }

    /// Retain WC system pages and map just the framebuffer's pitch*height
    /// extent. WB, USERPTR, local memory, non-SCANOUT and busy writers refuse
    /// before any PTE changes. The caller must order future GPU/CPU writes.
    pub fn prepare(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
    ) -> Result<SurfaceId, ScanoutError> {
        self.ready()?;
        if !object.is_wc() || !object.scanout() || object.is_vram() || object.is_userptr() {
            return Err(ScanoutError::Unsupported);
        }
        self.prepare_object(object, geometry)
    }

    fn prepare_object(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
    ) -> Result<SurfaceId, ScanoutError> {
        self.ready()?;
        let extent = geometry.extent()?;
        if extent > object.size() {
            return Err(ScanoutError::Bounds);
        }
        if !object.idle(false) {
            return Err(ScanoutError::Busy);
        }
        let pages = extent.div_ceil(GTT_PAGE_SIZE) as u32;
        let ptes: Vec<u64> = object
            .pages()
            .take(pages as usize)
            .map(|phys| self.format.encode_ggtt(phys, self.pat))
            .collect::<Result<_, _>>()
            .map_err(|_| ScanoutError::Bounds)?;
        if ptes.len() != pages as usize {
            return Err(ScanoutError::Bounds);
        }
        let slot = self
            .free
            .iter()
            .position(|&(_, n)| n >= pages)
            .ok_or(ScanoutError::Busy)?;
        if !object.publish_for_device() {
            return Err(ScanoutError::Unavailable);
        }
        let id = SurfaceId(self.next_id);
        let next = self.next_id.checked_add(1).ok_or(ScanoutError::Busy)?;
        let offset = self.free[slot].0;
        self.free[slot].0 += pages * 4096;
        self.free[slot].1 -= pages;
        if self.free[slot].1 == 0 {
            self.free.remove(slot);
        }
        self.next_id = next;
        // Ownership precedes the first hardware-visible write, including on
        // unavailable/readback/invalidation failure.
        self.surfaces.insert(
            id,
            Surface {
                object,
                offset,
                pages,
                geometry,
            },
        );
        for (i, &pte) in ptes.iter().enumerate() {
            self.write_pte(offset + i as u32 * 4096, pte);
        }
        let installed = ptes.iter().enumerate().all(|(i, &pte)| {
            let reg = GGTT_ARRAY_BASE + (u64::from(offset / 4096) + i as u64) * 8;
            self.io().read32(reg) == pte as u32 && self.io().read32(reg + 4) == (pte >> 32) as u32
        });
        if !installed || !self.post_ptes(offset + (pages - 1) * 4096) {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        Ok(id)
    }

    fn write_pte(&self, offset: u32, pte: u64) {
        let reg = GGTT_ARRAY_BASE + u64::from(offset / 4096) * 8;
        self.io().write32(reg, pte as u32);
        self.io().write32(reg + 4, (pte >> 32) as u32);
    }
    fn post_ptes(&self, last: u32) -> bool {
        compiler_fence(Ordering::SeqCst);
        let reg = GGTT_ARRAY_BASE + u64::from(last / 4096) * 8;
        let available = self.io().read32(reg) != u32::MAX && self.io().read32(reg + 4) != u32::MAX;
        available && self.io().invalidate_ggtt()
    }
    fn geometry_matches(&self, geometry: Geometry) -> bool {
        let ctl = self.io().read32(self.plane() + PLANE_CTL_OFFSET);
        let color = self.io().read32(self.plane() + COLOR_CTL_OFFSET);
        ctl != u32::MAX
            && ctl & !ALLOWED_CTL == 0
            && ctl & (PLANE_CTL_ENABLE | CTL_FORMAT_MASK | CTL_TILED_MASK | CTL_RGB_ORDER)
                == PLANE_CTL_ENABLE | CTL_XRGB8888
            && self.io().read32(self.plane() + PLANE_STRIDE_OFFSET) == geometry.pitch / 64
            && self.io().read32(self.plane() + PLANE_SIZE_OFFSET)
                == ((geometry.height - 1) << 16) | (geometry.width - 1)
            && self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) == 0
            && self.io().read32(self.plane() + AUX_DIST_OFFSET) == 0
            && self.io().read32(self.plane() + AUX_OFFSET_OFFSET) == 0
            && self.io().read32(self.plane() + CUS_CTL_OFFSET) == 0
            && color != u32::MAX
            && color & (3 << 4) == 0
    }

    fn faults(&self) -> u32 {
        // PIPEDMC fault is shared by TGL..MTL; MTL adds plane ATS and
        // PIPEDMC ATS faults in bits18/24 (old platforms use those bits for
        // other planes' flip-done and the DMC flip queue, respectively).
        let ats = if self.format == PteFormat::XeLpg {
            (1 << 18) | (1 << 24)
        } else {
            0
        };
        FIFO_UNDERRUN | PLANE_FAULT | (1 << 25) | ats
    }

    /// Arm only PLANE_SURF; leave timing, geometry, format and watermarks as
    /// established by modeset. One outstanding flip; callers cannot replace
    /// a pending buffer and accidentally release it before hardware sees it.
    pub fn arm(&mut self, id: SurfaceId, ticket: u64, now: u64) -> Result<(), ScanoutError> {
        self.ready()?;
        if self.pending.is_some() {
            return Err(ScanoutError::Busy);
        }
        let surface = self.surfaces.get(&id).ok_or(ScanoutError::UnknownSurface)?;
        if !surface.object.idle(false) {
            return Err(ScanoutError::Busy);
        }
        if !surface.object.publish_for_device() {
            return Err(ScanoutError::Unavailable);
        }
        if !self.geometry_matches(surface.geometry) {
            return Err(ScanoutError::Unsupported);
        }
        if self.io().read32(self.plane() + PLANE_SURF_OFFSET) != self.expected_surface
            || self.io().read32(self.plane() + SURFLIVE_OFFSET) != self.expected_surface
        {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        let iir = self.io().read32(self.iir());
        let frame = self.io().read32(self.pipe.base() + FRAMECOUNT_OFFSET);
        if frame == u32::MAX || iir & self.faults() != 0 {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        // A stale flip-done cannot complete a replacement of the same address.
        self.io().write32(self.iir(), PRIMARY_FLIP_DONE);
        if self.io().read32(self.iir()) & PRIMARY_FLIP_DONE != 0 {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        let offset = surface.offset;
        self.pending = Some(Pending {
            id,
            ticket,
            frame,
            deadline: now.saturating_add(FLIP_TIMEOUT_NS),
        });
        compiler_fence(Ordering::SeqCst);
        self.io().write32(self.plane() + PLANE_SURF_OFFSET, offset);
        if self.io().read32(self.plane() + PLANE_SURF_OFFSET) != offset {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        Ok(())
    }

    /// Bounded task-context observation, usable from an IRQ-driven worker or
    /// a timer. No polling loop, IRQ register unmask or fabricated completion.
    pub fn poll(&mut self, now: u64) -> Result<Option<Completion>, ScanoutError> {
        self.ready()?;
        let Some(pending) = self.pending else {
            return Ok(None);
        };
        let surface = &self.surfaces[&pending.id];
        let before = self.io().read32(self.pipe.base() + FRAMECOUNT_OFFSET);
        let live = self.io().read32(self.plane() + SURFLIVE_OFFSET);
        let status = self.io().read32(self.iir());
        let after = self.io().read32(self.pipe.base() + FRAMECOUNT_OFFSET);
        if before == u32::MAX || after == u32::MAX || status & self.faults() != 0 {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        if before == after
            && after != pending.frame
            && live == surface.offset
            && status & PRIMARY_FLIP_DONE != 0
        {
            if self.io().read32(self.plane() + PLANE_SURF_OFFSET) != surface.offset
                || !self.geometry_matches(surface.geometry)
            {
                self.failed = true;
                return Err(ScanoutError::Unavailable);
            }
            self.io().write32(self.iir(), PRIMARY_FLIP_DONE);
            self.expected_surface = surface.offset;
            let retired = self
                .current
                .replace(pending.id)
                .filter(|old| *old != pending.id);
            self.pending = None;
            return Ok(Some(Completion {
                surface: pending.id,
                ticket: pending.ticket,
                stamp: crate::drm::card::FlipStamp {
                    ns: now,
                    sequence: after,
                },
                retired,
            }));
        }
        if now >= pending.deadline {
            self.failed = true;
            return Err(ScanoutError::Timeout);
        }
        Ok(None)
    }

    /// Unmap a prepared or retired surface. Current/pending buffers stay
    /// retained. Address reuse follows posted clears and verified invalidation.
    pub fn release(&mut self, id: SurfaceId) -> Result<(), ScanoutError> {
        self.ready()?;
        if self.current == Some(id) || self.pending.is_some_and(|p| p.id == id) {
            return Err(ScanoutError::Busy);
        }
        let surface = self.surfaces.get(&id).ok_or(ScanoutError::UnknownSurface)?;
        let (offset, pages) = (surface.offset, surface.pages);
        if !self.clear(offset, pages) {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        self.surfaces.remove(&id);
        self.free.push((offset, pages));
        self.free.sort_unstable_by_key(|&(base, _)| base);
        let mut i = 0;
        while i + 1 < self.free.len() {
            if self.free[i].0 + self.free[i].1 * 4096 == self.free[i + 1].0 {
                let pages = self.free.remove(i + 1).1;
                self.free[i].1 += pages;
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    fn clear(&self, offset: u32, pages: u32) -> bool {
        for page in 0..pages {
            self.write_pte(offset + page * 4096, 0);
        }
        if !self.post_ptes(offset + (pages - 1) * 4096) {
            return false;
        }
        (0..pages).all(|page| {
            let reg = GGTT_ARRAY_BASE + u64::from(offset / 4096 + page) * 8;
            self.io().read32(reg) == 0 && self.io().read32(reg + 4) == 0
        })
    }

    /// Release all resources only after display fetch is independently proven
    /// stopped. Failed clear/invalidation keeps *all* object owners, including
    /// the pending and previous front buffer. No event is completed here.
    ///
    /// # Safety
    /// Caller has stopped and drained this plane/pipe (or verified a complete
    /// device reset) while retaining power, and excluded every other fetcher
    /// and CPU writer. A cleared PLANE_CTL enable request alone is not proof.
    pub unsafe fn shutdown_stopped(&mut self) -> Result<(), ScanoutError> {
        for surface in self.surfaces.values() {
            if !self.clear(surface.offset, surface.pages) {
                self.failed = true;
                return Err(ScanoutError::Unavailable);
            }
        }
        self.current = None;
        self.pending = None;
        self.surfaces.clear();
        self.closed = true;
        Ok(())
    }
}

impl<M: ScanoutIo> Drop for Presenter<M> {
    fn drop(&mut self) {
        if !self.surfaces.is_empty() {
            // A Rust drop, timeout or failed write does not stop display DMA.
            // Keep the RAM, mapping reservation and power/access owner alive.
            core::mem::forget(core::mem::take(&mut self.surfaces));
            core::mem::forget(self.io.take());
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_scanout_tests.rs"]
mod tests;
