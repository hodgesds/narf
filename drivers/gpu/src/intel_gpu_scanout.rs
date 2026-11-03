//! Owned linear/no-DPT X/Tile4 GEM scanout and primary-surface latch tracking.
//!
//! References: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! xe/display/xe_fb_pin.c, i915/display/{skl_universal_plane_regs.h,
//! intel_display_regs.h,intel_display_irq.c}. A PLANE_SURF write is an arm,
//! not completion: the previous buffer survives until fresh flip-done,
//! SURFLIVE and a stable changed hardware frame counter agree.
//!
//! The per-card intel_gpu_kms service supplies display power, console handoff,
//! modeset/PM exclusion and transactional event publication. Its PollIo adapter
//! enables status latching with IRQ delivery masked; this owner never invents
//! vblank completion or programs timing/geometry.

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
pub(crate) const X_TILED_MODIFIER: u64 = 0x0100_0000_0000_0001;
pub(crate) const TILE4_MODIFIER: u64 = 0x0100_0000_0000_0009;
// ICL+ arbitration slots and the harmless trickle-feed/clear-color disable
// controls may be inherited. All auxiliary/YUV/keying, compression, async,
// horizontal-flip and rotation bits must be clear for this linear surface.
const ALLOWED_CTL: u32 = PLANE_CTL_ENABLE | (7 << 28) | CTL_FORMAT_MASK | (1 << 14) | (1 << 13);
const AUX_DIST_OFFSET: u64 = 0x40;
const AUX_OFFSET_OFFSET: u64 = 0x44;
const CUS_CTL_OFFSET: u64 = 0x48;
const COLOR_CTL_OFFSET: u64 = 0x4c;
const FLIP_TIMEOUT_NS: u64 = 1_000_000_000;

pub(crate) fn gen12_alignment(family: crate::intel_gpu_gt::Gen12Platform) -> u32 {
    if matches!(
        family,
        crate::intel_gpu_gt::Gen12Platform::AlderLakeP
            | crate::intel_gpu_gt::Gen12Platform::AlderLakeN
    ) {
        16384
    } else {
        4096
    }
}
pub(crate) fn gen12_max_stride(family: crate::intel_gpu_gt::Gen12Platform) -> u32 {
    if gen12_alignment(family) == 16384 {
        128 * 1024
    } else {
        32 * 1024
    }
}

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

    /// A source-qualified fixed display14 opaque linear XR30 input profile.
    /// This is a retained current display/resource proof, not format discovery.
    fn supports_xr30(&self) -> bool {
        false
    }

    /// Retain only the exact original/current/pending primary controls owned
    /// by this presenter. Required before an XR30 DSB can be exposed and before
    /// fresh console recovery; it grants no arbitrary CPU format writes.
    fn retain_primary_controls(
        &self,
        _original: u32,
        _current: u32,
        _pending: Option<u32>,
    ) -> bool {
        false
    }
    fn retained_primary_control(&self, _control: u32) -> bool {
        false
    }

    /// Restore only the status bits owned by this presentation service.
    ///
    /// # Safety
    /// Every owned GEM mapping is independently proven no longer fetched;
    /// the inherited console may still scan. Current authority, power and
    /// exclusion of modeset/reset remain held through this operation.
    unsafe fn finish_stopped(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SurfaceId(u64);

/// An opaque cpp4 visible rectangle. Native format changes use the retained
/// joint DSB; surface-only flips retain the original XR24 format and geometry.
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

/// Integer source origin; destination geometry and bandwidth stay unchanged.
/// Linux intel_fb.c::intel_compute_aligned_offset splits a linear address
/// or tile address into a 4-KiB-aligned TGL+ SURF and residual PLANE_OFFSET.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Viewport {
    pub x: u32,
    pub y: u32,
}
impl Viewport {
    pub(crate) fn layout(self, geometry: Geometry) -> Result<(u32, u32, u64), ScanoutError> {
        geometry.extent()?;
        if self.x > 0xffff
            || self.y > 0xffff
            || self
                .x
                .checked_add(geometry.width)
                .is_none_or(|x| x > geometry.pitch / 4)
        {
            return Err(ScanoutError::Bounds);
        }
        let extent = u64::from(self.y)
            .checked_add(u64::from(geometry.height))
            .and_then(|rows| rows.checked_mul(u64::from(geometry.pitch)))
            .filter(|bytes| *bytes <= GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START)
            .ok_or(ScanoutError::Bounds)?;
        let start = u64::from(self.y) * u64::from(geometry.pitch) + u64::from(self.x) * 4;
        let residual = start % GTT_PAGE_SIZE;
        let y = residual / u64::from(geometry.pitch);
        let x = residual % u64::from(geometry.pitch) / 4;
        Ok((
            (start & !(GTT_PAGE_SIZE - 1)) as u32,
            ((y as u32) << 16) | x as u32,
            extent,
        ))
    }
}

/// Fixed primary layout. X/Tile4 use the source-qualified MTL no-DPT path;
/// neither auxiliary compression nor a display page-table pointer is accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Layout {
    #[default]
    Linear,
    X,
    Tile4,
}
/// Opaque 32-bit primary input. Output link depth and colorimetry are unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum InputFormat {
    #[default]
    Xrgb8888,
    Xrgb2101010,
}
impl InputFormat {
    pub(crate) fn control(self) -> u32 {
        match self {
            Self::Xrgb8888 => CTL_XRGB8888,
            Self::Xrgb2101010 => 0x02000000,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct View {
    pub(crate) origin: Viewport,
    pub(crate) layout: Layout,
    pub(crate) input: InputFormat,
}
impl From<Viewport> for View {
    fn from(origin: Viewport) -> Self {
        Self {
            origin,
            layout: Layout::Linear,
            input: InputFormat::Xrgb8888,
        }
    }
}
impl View {
    pub(crate) fn footprint(self, geometry: Geometry) -> Result<(u32, u32, u64), ScanoutError> {
        if self.input == InputFormat::Xrgb2101010 && self.layout != Layout::Linear {
            return Err(ScanoutError::Unsupported);
        }
        if self.layout == Layout::Linear {
            return self.origin.layout(geometry);
        }
        geometry.extent()?;
        let tile_width = if self.layout == Layout::X { 512 } else { 128 };
        let tile_height = 4096 / tile_width;
        let tile_pixels = tile_width / 4;
        // intel_tile_width_bytes and intel_tile_height for plain X/Tile4.
        // The no-DPT surface alignment is exactly one tile. Decompose the
        // source as intel_compute_aligned_offset, without stride remapping.
        if geometry.pitch % tile_width != 0
            || geometry.pitch > 128 * 1024
            || !(4..=5120).contains(&geometry.width)
            || geometry.height > 4320
        {
            return Err(ScanoutError::Unsupported);
        }
        if self.origin.x > 0xffff
            || self.origin.y > 0xffff
            || self
                .origin
                .x
                .checked_add(geometry.width)
                .is_none_or(|end| end > geometry.pitch / 4)
        {
            // In particular residualX+width cannot exceed the tile stride
            // (skl_calc_main_surface_offset's X-tile overfetch restriction).
            return Err(ScanoutError::Bounds);
        }
        let rows = (u64::from(self.origin.y) + u64::from(geometry.height))
            .div_ceil(u64::from(tile_height))
            * u64::from(tile_height);
        let bytes = rows * u64::from(geometry.pitch);
        if bytes > GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START {
            return Err(ScanoutError::Bounds);
        }
        let tile = u64::from(self.origin.y / tile_height) * u64::from(geometry.pitch / tile_width)
            + u64::from(self.origin.x / tile_pixels);
        Ok((
            (tile * GTT_PAGE_SIZE) as u32,
            (self.origin.y % tile_height) << 16 | (self.origin.x % tile_pixels),
            bytes,
        ))
    }
    /// Linux intel_compute_aligned_offset + intel_adjust_tile_offset. ADLP/N
    /// use 16KiB SURF alignment even for synchronous linear/X replacements.
    pub(crate) fn footprint_aligned(
        self,
        geometry: Geometry,
        alignment: u32,
    ) -> Result<(u32, u32, u64), ScanoutError> {
        let (base, offset, bytes) = self.footprint(geometry)?;
        if ![4096, 16384].contains(&alignment) {
            return Err(ScanoutError::Unsupported);
        }
        let aligned = base & !(alignment - 1);
        if self.layout == Layout::Linear {
            let start =
                u64::from(self.origin.y) * u64::from(geometry.pitch) + u64::from(self.origin.x) * 4;
            let residual = start - u64::from(aligned);
            let y = residual / u64::from(geometry.pitch);
            let x = residual % u64::from(geometry.pitch) / 4;
            if x > 0xffff || y > 0xffff {
                return Err(ScanoutError::Bounds);
            }
            return Ok((aligned, (y as u32) << 16 | x as u32, bytes));
        }
        let tile_width = if self.layout == Layout::X { 128 } else { 32 };
        let tile_height = if self.layout == Layout::X { 8 } else { 32 };
        let pitch_tiles = geometry.pitch / (tile_width * 4);
        let delta = (base - aligned) / 4096;
        let mut y = (offset >> 16) + (delta / pitch_tiles) * tile_height;
        let mut x = (offset & 0xffff) + (delta % pitch_tiles) * tile_width;
        y += x / (pitch_tiles * tile_width) * tile_height;
        x %= pitch_tiles * tile_width;
        if x + geometry.width > geometry.pitch / 4 || x > 0xffff || y > 0xffff {
            return Err(ScanoutError::Bounds);
        }
        Ok((aligned, y << 16 | x, bytes))
    }
    pub(crate) fn stride(self, geometry: Geometry) -> u32 {
        geometry.pitch
            / match self.layout {
                Layout::Linear => 64,
                Layout::X => 512,
                Layout::Tile4 => 128,
            }
    }
    pub(crate) fn tiled(self) -> u32 {
        match self.layout {
            Layout::Linear => 0,
            Layout::X => 1 << 10,
            Layout::Tile4 => 5 << 10,
        }
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
    view: View,
}
#[derive(Clone, Copy)]
struct Pending {
    id: SurfaceId,
    offset: u32,
    geometry: Geometry,
    view: View,
    plane_offset: u32,
    ticket: u64,
    frame: u32,
    deadline: u64,
    deferred: bool,
}
#[derive(Clone, Copy)]
struct Target {
    offset: u32,
    geometry: Geometry,
    view: View,
    plane_offset: u32,
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
    alignment: u32,
    gen12_family: Option<crate::intel_gpu_gt::Gen12Platform>,
    free: Vec<(u32, u32)>,
    surfaces: BTreeMap<SurfaceId, Surface>,
    next_id: u64,
    current: Option<SurfaceId>,
    console_surface: u32,
    console_geometry: Option<Geometry>,
    expected_surface: u32,
    expected_offset: u32,
    console_ctl: u32,
    expected_view: View,
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
        let console_ctl = io.read32(pipe.base() + PLANE_PRIMARY_OFFSET + PLANE_CTL_OFFSET);
        if console_ctl & CTL_TILED_MASK != 0 {
            return Err(ScanoutError::Unsupported);
        }
        let owner = Self {
            io: Some(io),
            pipe,
            format,
            pat,
            alignment: 4096,
            gen12_family: None,
            free: alloc::vec![(
                GEM_SCANOUT_GTT_START as u32,
                ((GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START) / GTT_PAGE_SIZE) as u32,
            )],
            surfaces: BTreeMap::new(),
            next_id: 1,
            current: None,
            console_surface: initial_surface,
            console_geometry: None,
            expected_surface: initial_surface,
            expected_offset: 0,
            console_ctl,
            expected_view: View::default(),
            pending: None,
            failed: false,
            closed: false,
        };
        if owner.io().read32(owner.plane() + PLANE_SURF_OFFSET) != initial_surface
            || owner.io().read32(owner.plane() + SURFLIVE_OFFSET) != initial_surface
            || owner.io().read32(owner.plane() + PLANE_OFFSET_OFFSET) != 0
        {
            return Err(ScanoutError::Unavailable);
        }
        Ok(owner)
    }

    fn io(&self) -> &M {
        self.io.as_ref().expect("scanout owner")
    }
    pub(crate) fn retained_io(&self) -> &M {
        self.io()
    }
    pub(crate) fn console_control(&self) -> u32 {
        self.console_ctl
    }
    fn control(&self, view: View) -> u32 {
        (self.console_ctl & !(CTL_FORMAT_MASK | CTL_TILED_MASK))
            | view.input.control()
            | view.tiled()
    }
    pub(crate) fn tracks_xr30(&self) -> bool {
        self.expected_view.input == InputFormat::Xrgb2101010
            || self
                .pending
                .is_some_and(|p| p.view.input == InputFormat::Xrgb2101010)
    }
    pub(crate) fn retained_primary_controls(&self) -> (u32, u32, Option<u32>) {
        (
            self.console_ctl,
            self.control(self.expected_view),
            self.pending.map(|p| self.control(p.view)),
        )
    }
    fn retain_controls(&self, pending: Option<View>) -> Result<(), ScanoutError> {
        if (self.expected_view.input == InputFormat::Xrgb2101010
            || pending.is_some_and(|v| v.input == InputFormat::Xrgb2101010))
            && (!self.io().supports_xr30()
                || !self.io().retain_primary_controls(
                    self.console_ctl,
                    self.control(self.expected_view),
                    pending.map(|v| self.control(v)),
                ))
        {
            return Err(ScanoutError::Unavailable);
        }
        Ok(())
    }

    /// Start a fresh console transaction without accepting any pre-loss
    /// SURF/SURFLIVE sample as retirement of the previous owner's pages.
    /// This temporary owner never allocates or adopts the old arena.
    ///
    /// # Safety
    /// The caller retains every old current/pending allocation and the
    /// console allocation, exclusively owns this plane/arena, has restored
    /// and verified GT cache policy and supplies a new live status owner.
    /// For Gen12 X, the caller also retains the exact family/no-DPT witness
    /// before this temporary parser accepts an old owned tiled plane image.
    /// Only a successful fresh console latch permits reclaiming old pages.
    pub(crate) unsafe fn recover_console(
        io: M,
        bar_len: u64,
        pipe: Pipe,
        format: PteFormat,
        pat: u8,
        target: (u32, Geometry, u32, u64),
    ) -> Result<Self, ScanoutError> {
        let (console, geometry, console_ctl, now) = target;
        if console_ctl == u32::MAX || console_ctl & CTL_TILED_MASK != 0 {
            return Err(ScanoutError::Unsupported);
        }
        check_ggtt_range(
            bar_len,
            GEM_SCANOUT_GTT_START,
            GEM_SCANOUT_GTT_END - GEM_SCANOUT_GTT_START,
        )
        .map_err(|_| ScanoutError::Bounds)?;
        geometry.extent()?;
        format
            .encode_ggtt(0, pat)
            .map_err(|_| ScanoutError::Unsupported)?;
        if console % 4096 != 0
            || (GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(console))
        {
            return Err(ScanoutError::Bounds);
        }
        let mut owner = Self {
            io: Some(io),
            pipe,
            format,
            pat,
            alignment: 4096,
            gen12_family: None,
            free: alloc::vec![],
            surfaces: BTreeMap::new(),
            next_id: 1,
            current: None,
            console_surface: console,
            console_geometry: Some(geometry),
            expected_surface: console,
            expected_offset: 0,
            console_ctl,
            expected_view: View::default(),
            pending: None,
            failed: false,
            closed: false,
        };
        let ctl = owner.io().read32(owner.plane() + PLANE_CTL_OFFSET);
        if ctl & CTL_TILED_MASK == 1 << 10 {
            owner.expected_view.layout = Layout::X;
        } else if ctl & CTL_TILED_MASK == 5 << 10 {
            owner.expected_view.layout = Layout::Tile4;
        }
        if ctl & CTL_FORMAT_MASK == InputFormat::Xrgb2101010.control() {
            if owner.format != PteFormat::XeLpg
                || !owner.io().supports_xr30()
                || !owner.io().retained_primary_control(ctl)
            {
                return Err(ScanoutError::Unsupported);
            }
            owner.expected_view.input = InputFormat::Xrgb2101010;
        }
        let stride = owner.io().read32(owner.plane() + PLANE_STRIDE_OFFSET);
        // An interrupted owned arm may have changed STRIDE but not CTL (or
        // vice versa). Only the retained fixed layout pitches are admissible;
        // neither mixed readback is accepted as completion/retirement.
        if !(stride == geometry.pitch / 64
            || (geometry.pitch % 512 == 0 && stride == geometry.pitch / 512)
            || (geometry.pitch % 128 == 0 && stride == geometry.pitch / 128))
            || !owner.geometry_matches_stride(geometry, owner.expected_view, stride)
        {
            return Err(ScanoutError::Unsupported);
        }
        owner.arm_observed(
            SurfaceId(0),
            Target {
                offset: console,
                geometry,
                view: View::default(),
                plane_offset: 0,
            },
            0,
            now,
            false,
        )?;
        Ok(owner)
    }
    pub(crate) fn qualify_gen12(
        &mut self,
        family: crate::intel_gpu_gt::Gen12Platform,
    ) -> Result<(), ScanoutError> {
        if self.format != PteFormat::Gen12
            || self.pending.is_some()
            || !self.surfaces.is_empty()
            || self.current.is_some()
        {
            return Err(ScanoutError::Busy);
        }
        if self.console_ctl != crate::intel_gpu_pipes::gen12_xrgb_control(family) {
            return Err(ScanoutError::Unsupported);
        }
        self.alignment = gen12_alignment(family);
        self.gen12_family = Some(family);
        Ok(())
    }
    fn no_dpt(&self, layout: Layout) -> bool {
        if layout == Layout::Linear {
            return true;
        }
        // intel_dpt_common.c::intel_dpt_configure sets the PLANE_CHICKEN
        // no-DPT bit on display 14 only: a display-20 tiled primary needs a
        // DPT this owner does not build.
        if self.format == PteFormat::Xe2 {
            return false;
        }
        if self.format == PteFormat::Gen12 {
            if layout != Layout::X {
                return false;
            }
            return self.gen12_family.is_none_or(|family| {
                !matches!(
                    family,
                    crate::intel_gpu_gt::Gen12Platform::AlderLakeP
                        | crate::intel_gpu_gt::Gen12Platform::AlderLakeN
                ) || {
                    let v = self.io().read32(0x42084);
                    v != u32::MAX && v & (1 << 30) != 0
                }
            });
        }
        let v = self.io().read32(0x7026c);
        v != u32::MAX && v & (1 << 19) != 0
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

    pub(crate) fn prepare_layout(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
        view: View,
    ) -> Result<SurfaceId, ScanoutError> {
        if view.input == InputFormat::Xrgb2101010
            && (self.format != PteFormat::XeLpg
                || view.layout != Layout::Linear
                || !self.io().supports_xr30())
        {
            return Err(ScanoutError::Unsupported);
        }
        if view.layout != Layout::Linear
            && (!self.no_dpt(view.layout)
                || (self.format == PteFormat::Gen12 && self.gen12_family.is_none()))
        {
            return Err(ScanoutError::Unsupported);
        }
        if !object.is_wc() || !object.scanout() || object.is_vram() || object.is_userptr() {
            return Err(ScanoutError::Unsupported);
        }
        self.prepare_object_view(object, geometry, view)
    }

    pub(crate) fn linear_surface(&self, id: SurfaceId) -> bool {
        self.surfaces
            .get(&id)
            .is_some_and(|s| s.view.layout == Layout::Linear)
    }
    pub(crate) fn check_current(&self, geometry: Geometry) -> Result<(), ScanoutError> {
        self.ready()?;
        if self.pending.is_some() {
            return Err(ScanoutError::Busy);
        }
        if !self.geometry_matches(geometry, self.expected_view)
            || self.io().read32(self.plane() + PLANE_SURF_OFFSET) != self.expected_surface
            || self.io().read32(self.plane() + SURFLIVE_OFFSET) != self.expected_surface
            || self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != self.expected_offset
        {
            return Err(ScanoutError::Unavailable);
        }
        Ok(())
    }
    pub(crate) fn matches_view(&self, id: SurfaceId, geometry: Geometry, view: View) -> bool {
        self.surfaces
            .get(&id)
            .is_some_and(|surface| surface.geometry == geometry && surface.view == view)
    }

    fn prepare_object(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
    ) -> Result<SurfaceId, ScanoutError> {
        self.prepare_object_view(object, geometry, View::default())
    }

    fn prepare_object_view(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
        view: View,
    ) -> Result<SurfaceId, ScanoutError> {
        self.ready()?;
        let (_, _, extent) = view.footprint_aligned(geometry, self.alignment)?;
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
            .map(|phys| crate::intel_gpu_gtt::encode_display_pte(self.format, phys, self.pat))
            .collect::<Result<_, _>>()
            .map_err(|_| ScanoutError::Bounds)?;
        if ptes.len() != pages as usize {
            return Err(ScanoutError::Bounds);
        }
        let (slot, offset, prefix) = self
            .free
            .iter()
            .enumerate()
            .find_map(|(slot, &(start, n))| {
                let aligned = (start + self.alignment - 1) & !(self.alignment - 1);
                let prefix = (aligned - start) / 4096;
                (n >= pages + prefix).then_some((slot, aligned, prefix))
            })
            .ok_or(ScanoutError::Busy)?;
        if !object.publish_for_device() {
            return Err(ScanoutError::Unavailable);
        }
        let id = SurfaceId(self.next_id);
        let next = self.next_id.checked_add(1).ok_or(ScanoutError::Busy)?;
        let (start, available) = self.free.remove(slot);
        if prefix != 0 {
            self.free.push((start, prefix));
        }
        if available > pages + prefix {
            self.free
                .push((offset + pages * 4096, available - pages - prefix));
        }
        self.free.sort_unstable_by_key(|&(base, _)| base);
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
                view,
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
    fn geometry_matches(&self, geometry: Geometry, view: View) -> bool {
        self.geometry_matches_stride(geometry, view, view.stride(geometry))
    }
    fn geometry_matches_stride(&self, geometry: Geometry, view: View, stride: u32) -> bool {
        let ctl = self.io().read32(self.plane() + PLANE_CTL_OFFSET);
        let color = self.io().read32(self.plane() + COLOR_CTL_OFFSET);

        ctl != u32::MAX
            && ctl & !(ALLOWED_CTL | CTL_TILED_MASK) == 0
            && ctl & (PLANE_CTL_ENABLE | CTL_FORMAT_MASK | CTL_TILED_MASK | CTL_RGB_ORDER)
                == PLANE_CTL_ENABLE | view.input.control() | view.tiled()
            && ctl == self.control(view)
            && self.no_dpt(view.layout)
            && self.io().read32(self.plane() + PLANE_STRIDE_OFFSET) == stride
            && self.io().read32(self.plane() + PLANE_SIZE_OFFSET)
                == ((geometry.height - 1) << 16) | (geometry.width - 1)
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
        // Display 20 (gen8_de_pipe_fault_mask, DISPLAY_VER >= 20) keeps the
        // plane ATS fault and drops both PIPEDMC faults.
        match self.format {
            PteFormat::Xe2 => FIFO_UNDERRUN | PLANE_FAULT | (1 << 18),
            PteFormat::XeLpg => FIFO_UNDERRUN | PLANE_FAULT | (1 << 25) | (1 << 18) | (1 << 24),
            PteFormat::Gen12 => FIFO_UNDERRUN | PLANE_FAULT | (1 << 25),
        }
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
        if surface.view != View::default()
            || self.expected_view.input != InputFormat::Xrgb8888
            || self.expected_view.layout != Layout::Linear
        {
            return Err(ScanoutError::Unsupported);
        }
        if !surface.object.idle(false) {
            return Err(ScanoutError::Busy);
        }
        if !surface.object.publish_for_device() {
            return Err(ScanoutError::Unavailable);
        }
        let (base, plane_offset, _) = surface
            .view
            .footprint_aligned(surface.geometry, self.alignment)?;
        let (offset, geometry) = (surface.offset + base, surface.geometry);
        self.arm_target(
            id,
            Target {
                offset,
                geometry,
                view: surface.view,
                plane_offset,
            },
            ticket,
            now,
            false,
        )
    }

    /// Retain a pending target and fresh primary completion status without
    /// writing SURF. The exclusive KMS owner emits the returned arm in its
    /// source-qualified DSB safe window, after color arm registers.
    pub(crate) fn stage_dsb(
        &mut self,
        id: SurfaceId,
        ticket: u64,
        now: u64,
    ) -> Result<Vec<(u64, u32)>, ScanoutError> {
        self.ready()?;
        let surface = self.surfaces.get(&id).ok_or(ScanoutError::UnknownSurface)?;
        if !surface.object.idle(false) {
            return Err(ScanoutError::Busy);
        }
        if !surface.object.publish_for_device() {
            return Err(ScanoutError::Unavailable);
        }
        let (base, plane_offset, _) = surface
            .view
            .footprint_aligned(surface.geometry, self.alignment)?;
        let view = surface.view;
        let (offset, geometry) = (surface.offset + base, surface.geometry);
        self.arm_target(
            id,
            Target {
                offset,
                geometry,
                view,
                plane_offset,
            },
            ticket,
            now,
            true,
        )?;
        let mut registers = alloc::vec![
            (self.plane() + PLANE_OFFSET_OFFSET, plane_offset),
            (self.plane() + PLANE_SURF_OFFSET, offset),
        ];
        if self.io().read32(self.plane() + PLANE_STRIDE_OFFSET) != view.stride(geometry)
            || self.io().read32(self.plane() + PLANE_CTL_OFFSET) != self.control(view)
        {
            registers.insert(
                0,
                (self.plane() + PLANE_STRIDE_OFFSET, view.stride(geometry)),
            );
            registers.insert(2, (self.plane() + PLANE_CTL_OFFSET, self.control(view)));
        }
        Ok(registers)
    }
    /// Roll back only an externally staged target whose DSB was never armed.
    ///
    /// # Safety
    /// Caller proves no command stream capable of issuing this staged SURF
    /// write was exposed/triggered. Cancellation after DSB arming must retain
    /// the pending target through ordinary completion or fresh recovery.
    pub(crate) unsafe fn cancel_staged_dsb(&mut self) -> Result<(), ScanoutError> {
        self.ready()?;
        if !self.pending.is_some_and(|pending| pending.deferred) {
            return Err(ScanoutError::Busy);
        }
        if self.io().read32(self.plane() + PLANE_SURF_OFFSET) != self.expected_surface
            || self.io().read32(self.plane() + SURFLIVE_OFFSET) != self.expected_surface
            || self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != self.expected_offset
            || !self.geometry_matches(
                self.console_geometry.ok_or(ScanoutError::Unsupported)?,
                self.expected_view,
            )
        {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        self.pending = None;
        self.retain_controls(None)?;
        Ok(())
    }

    /// Restore the retained console surface through the same fresh hardware
    /// latch proof as a GEM flip. Surface zero is reserved for this target.
    pub fn arm_console(&mut self, ticket: u64, now: u64) -> Result<(), ScanoutError> {
        let geometry = self.console_geometry.ok_or(ScanoutError::Unsupported)?;
        self.arm_target(
            SurfaceId(0),
            Target {
                offset: self.console_surface,
                geometry,
                view: View::default(),
                plane_offset: 0,
            },
            ticket,
            now,
            false,
        )
    }

    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }

    pub fn console_active(&self) -> bool {
        !self.failed
            && !self.closed
            && self.current.is_none()
            && self.pending.is_none()
            && self.expected_surface == self.console_surface
            && self.expected_offset == 0
            && self.expected_view == View::default()
    }

    fn arm_target(
        &mut self,
        id: SurfaceId,
        target: Target,
        ticket: u64,
        now: u64,
        deferred: bool,
    ) -> Result<(), ScanoutError> {
        self.ready()?;
        if self.pending.is_some() {
            return Err(ScanoutError::Busy);
        }
        if !self.geometry_matches(target.geometry, self.expected_view)
            || self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != self.expected_offset
        {
            return Err(ScanoutError::Unsupported);
        }
        if self.io().read32(self.plane() + PLANE_SURF_OFFSET) != self.expected_surface
            || self.io().read32(self.plane() + SURFLIVE_OFFSET) != self.expected_surface
        {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        self.arm_observed(id, target, ticket, now, deferred)
    }

    fn arm_observed(
        &mut self,
        id: SurfaceId,
        target: Target,
        ticket: u64,
        now: u64,
        deferred: bool,
    ) -> Result<(), ScanoutError> {
        let Target {
            offset,
            geometry,
            view,
            plane_offset,
        } = target;
        self.retain_controls(Some(view))?;
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
        self.console_geometry.get_or_insert(geometry);
        self.pending = Some(Pending {
            id,
            offset,
            geometry,
            view,
            plane_offset,
            ticket,
            frame,
            deadline: now.saturating_add(FLIP_TIMEOUT_NS),
            deferred,
        });
        if deferred {
            return Ok(());
        }
        compiler_fence(Ordering::SeqCst);
        if self.io().read32(self.plane() + PLANE_STRIDE_OFFSET) != view.stride(geometry)
            || self.io().read32(self.plane() + PLANE_CTL_OFFSET) != self.control(view)
        {
            // Internal console restoration only: STRIDE and CTL are shadowed
            // until SURF while the primary remains enabled. No client mixed
            // transaction uses CPU layout changes.
            self.io()
                .write32(self.plane() + PLANE_STRIDE_OFFSET, view.stride(geometry));
            self.io()
                .write32(self.plane() + PLANE_CTL_OFFSET, self.control(view));
            if !self.geometry_matches(geometry, view) {
                self.failed = true;
                return Err(ScanoutError::Unavailable);
            }
        }
        // PLANE_OFFSET is double-buffered with the final SURF arm. CPU use
        // here is limited to zero-origin flips/restoration; panning is emitted
        // through the DSB's source-qualified common safe window.
        if self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != plane_offset {
            self.io()
                .write32(self.plane() + PLANE_OFFSET_OFFSET, plane_offset);
            if self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != plane_offset {
                self.failed = true;
                return Err(ScanoutError::Unavailable);
            }
        }
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
            && live == pending.offset
            && status & PRIMARY_FLIP_DONE != 0
        {
            if self.io().read32(self.plane() + PLANE_SURF_OFFSET) != pending.offset
                || self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != pending.plane_offset
                || !self.geometry_matches(pending.geometry, pending.view)
            {
                self.failed = true;
                return Err(ScanoutError::Unavailable);
            }
            self.io().write32(self.iir(), PRIMARY_FLIP_DONE);
            let xr30_transition = self.expected_view.input == InputFormat::Xrgb2101010
                || pending.view.input == InputFormat::Xrgb2101010;
            self.expected_surface = pending.offset;
            self.expected_offset = pending.plane_offset;
            self.expected_view = pending.view;
            let retired = if pending.id == SurfaceId(0) {
                self.current.take()
            } else {
                self.current
                    .replace(pending.id)
                    .filter(|old| *old != pending.id)
            };
            self.pending = None;
            // Retain the exact completed image through later console restore.
            if xr30_transition
                && !self.io().retain_primary_controls(
                    self.console_ctl,
                    self.control(self.expected_view),
                    None,
                )
            {
                self.failed = true;
                return Err(ScanoutError::Unavailable);
            }
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

    /// Reobserve an independently completed surface without consuming another
    /// flip-done or releasing the old mapping. The KMS joint owner retains the
    /// original Completion and brackets this with its color/DSB observation.
    pub(crate) fn observe_completed(
        &self,
        completion: &Completion,
        now: u64,
    ) -> Result<Option<crate::drm::card::FlipStamp>, ScanoutError> {
        self.ready()?;
        if self.pending.is_some() || self.current != Some(completion.surface) {
            return Err(ScanoutError::Busy);
        }
        let geometry = self.console_geometry.ok_or(ScanoutError::Unsupported)?;
        let before = self.io().read32(self.pipe.base() + FRAMECOUNT_OFFSET);
        let live = self.io().read32(self.plane() + SURFLIVE_OFFSET);
        let status = self.io().read32(self.iir());
        if before == u32::MAX
            || status & self.faults() != 0
            || live != self.expected_surface
            || self.io().read32(self.plane() + PLANE_SURF_OFFSET) != self.expected_surface
            || self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != self.expected_offset
            || !self.geometry_matches(geometry, self.expected_view)
        {
            return Err(ScanoutError::Unavailable);
        }
        let after = self.io().read32(self.pipe.base() + FRAMECOUNT_OFFSET);
        if after == u32::MAX {
            return Err(ScanoutError::Unavailable);
        }
        Ok((before == after).then_some(crate::drm::card::FlipStamp {
            ns: now,
            sequence: after,
        }))
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
        Self::clear_with(self.io(), offset, pages)
    }
    fn clear_with(io: &M, offset: u32, pages: u32) -> bool {
        for page in 0..pages {
            let reg = GGTT_ARRAY_BASE + u64::from(offset / 4096 + page) * 8;
            io.write32(reg, 0);
            io.write32(reg + 4, 0);
        }
        compiler_fence(Ordering::SeqCst);
        if !io.invalidate_ggtt() {
            return false;
        }
        (0..pages).all(|page| {
            let reg = GGTT_ARRAY_BASE + u64::from(offset / 4096 + page) * 8;
            io.read32(reg) == 0 && io.read32(reg + 4) == 0
        })
    }

    /// Reclaim a poisoned owner using an independent fresh console latch.
    /// Its original IO remains lost and is never revived or used to clear
    /// mappings. Failed posting or status restoration retains *all* pages.
    ///
    /// # Safety
    /// `replacement` has independently latched the retained console after
    /// loss, proving no old current/pending surface is still fetched. It
    /// owns the same arena/status and inherited original IRQ ownership.
    pub(crate) unsafe fn shutdown_retired_with(
        &mut self,
        replacement: &M,
    ) -> Result<(), ScanoutError> {
        for surface in self.surfaces.values() {
            if !Self::clear_with(replacement, surface.offset, surface.pages) {
                self.failed = true;
                return Err(ScanoutError::Unavailable);
            }
        }
        // SAFETY: the caller supplies the independent fresh-latch proof.
        if !unsafe { replacement.finish_stopped() } {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        self.current = None;
        self.pending = None;
        self.surfaces.clear();
        self.closed = true;
        Ok(())
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
        self.finish_shutdown()
    }

    /// Reclaim after our console latch retired every owned GEM fetch. The
    /// console backing itself remains retained by the enclosing display owner.
    pub fn shutdown_restored_console(&mut self) -> Result<(), ScanoutError> {
        self.ready()?;
        if !self.console_active()
            || self.io().read32(self.plane() + PLANE_SURF_OFFSET) != self.console_surface
            || self.io().read32(self.plane() + SURFLIVE_OFFSET) != self.console_surface
            || self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != 0
            || self
                .console_geometry
                .is_some_and(|geometry| !self.geometry_matches(geometry, View::default()))
        {
            return Err(ScanoutError::Busy);
        }
        // SAFETY: no GEM flip remains pending, and either no GEM was ever
        // armed or our fresh console latch retired its last hardware fetch.
        // The constructor excludes all other users of this reserved arena.
        unsafe { self.shutdown_stopped() }
    }

    /// Finalize only after the caller's stop/console-latch proof and all
    /// owned PTE clears have completed. Failed status restoration retains RAM.
    fn finish_shutdown(&mut self) -> Result<(), ScanoutError> {
        // SAFETY: invoked only by shutdown paths after their no-fetch proof.
        if !unsafe { self.io().finish_stopped() } {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
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
