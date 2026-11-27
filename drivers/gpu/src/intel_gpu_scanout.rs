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
//!
//! Display 20 has no no-DPT chicken, so its X/Tile4 surfaces are fetched
//! through a display page table this owner builds ([`DptLayout`]).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gem::{GemObject, GemState, Placement};
use crate::intel_gpu_gtt::{
    check_ggtt_range, PteFormat, GEM_SCANOUT_GTT_END, GEM_SCANOUT_GTT_START, GGTT_ARRAY_BASE,
    GTT_PAGE_SIZE,
};
use crate::intel_gpu_pipes::{
    Pipe, PLANE_CTL_ENABLE, PLANE_CTL_OFFSET, PLANE_OFFSET_OFFSET, PLANE_PRIMARY_OFFSET,
    PLANE_SIZE_OFFSET, PLANE_STRIDE_OFFSET, PLANE_SURF_OFFSET,
};

const SURFLIVE_OFFSET: u64 = 0x2c;
/// `PLANE_SURF_DECRYPT` (`skl_plane_surf_offset` with
/// `plane_state->decrypt`).
pub(crate) const PLANE_SURF_DECRYPT: u32 = 1 << 2;
/// `PLANE_COLOR_PLANE_CSC_ENABLE`.
pub(crate) const PLANE_COLOR_CSC_ENABLE: u32 = 1 << 21;
/// The primary plane's `PLANE_CSC_COEFF(0..5)`, `PLANE_CSC_PREOFF(0..2)`
/// and `PLANE_CSC_POSTOFF(0..2)` past its base (`_PLANE_CSC_RY_GY_1_A`
/// 0x70210, `_PLANE_CSC_PREOFF_HI_1_A` 0x70228, `_PLANE_CSC_POSTOFF_HI_1_A`
/// 0x70234): what `icl_plane_csc_load_black` zeroes.
pub(crate) const PLANE_CSC_BLACK: [u64; 12] = [
    0x90, 0x94, 0x98, 0x9c, 0xa0, 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc,
];
const FRAMECOUNT_OFFSET: u64 = 0x40;
const PIPE_IIR_BASE: u64 = 0x44408;
const PRIMARY_FLIP_DONE: u32 = 1 << 3;
const PLANE_FAULT: u32 = 1 << 7;
const FIFO_UNDERRUN: u32 = 1 << 31;
const CTL_FORMAT_MASK: u32 = 0x1f << 23;
const CTL_TILED_MASK: u32 = 7 << 10;
/// `PLANE_CTL_RENDER_DECOMPRESSION_ENABLE`, `PLANE_CTL_CLEAR_COLOR_DISABLE`
/// and `PLANE_CTL_MEDIA_DECOMPRESSION_ENABLE`: set only by a compressed view.
const CTL_DECOMPRESSION_MASK: u32 = (1 << 15) | (1 << 13) | (1 << 4);
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

/// SKL surface alignment (bytes) for a linear primary plane:
/// `skl_plane_min_alignment` in Linux
/// (`display/skl_universal_plane.c`), selected for
/// DISPLAY_VER < 12. Linear and X-tiled surfaces pin at 256 KiB
/// (the VT-d floor); Y-tiled would need 1 MiB, but this driver
/// only places linear surfaces. This is a GGTT *pinning*
/// alignment, not a PLANE_SURF register constraint (SURF takes
/// a 4K-aligned GGTT offset); the modeset enforces it for Gen11
/// and Gen9 placements (the same SKL rule on both).
pub(crate) fn skl_alignment() -> u32 {
    256 * 1024
}

/// SKL maximum plane stride (bytes): `skl_plane_max_stride`
/// (`display/skl_universal_plane.c`), selected for
/// DISPLAY_VER < 13 — 8192 pixels / 32 KiB.
pub(crate) fn skl_max_stride() -> u32 {
    32 * 1024
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
    /// A compressed Tile4 layout (`narf.intel.ccs=1`, [`ccs`]): its AUX and
    /// clear-colour planes, `skl_plane_ctl_tiling`'s decompression bits.
    pub(crate) ccs: Option<ccs::CcsPlanes>,
}
impl From<Viewport> for View {
    fn from(origin: Viewport) -> Self {
        Self {
            origin,
            layout: Layout::Linear,
            input: InputFormat::Xrgb8888,
            ccs: None,
        }
    }
}
impl View {
    pub(crate) fn footprint(self, geometry: Geometry) -> Result<(u32, u32, u64), ScanoutError> {
        if self.input == InputFormat::Xrgb2101010 && self.layout != Layout::Linear {
            return Err(ScanoutError::Unsupported);
        }
        if let Some(ccs) = self.ccs {
            // A compressed primary is Tile4 with its CCS planes, in GGTT at
            // Linux's placement for the view's origin (`skl_check_main_surface`
            // over `skl_check_ccs_aux_surface`: the main surface 16 KiB
            // aligned, its x/y matching the AUX plane's, which has none of
            // its own). The mapping covers the main rows the view fetches and
            // the AUX plane the display fetches at PLANE_AUX_DIST. A
            // display-20 flat-CCS view is placed through its DPT instead
            // ([`DptLayout::ccs`]).
            if self.layout != Layout::Tile4 {
                return Err(ScanoutError::Unsupported);
            }
            let view = View { ccs: None, ..self };
            let (_, _, bytes) = view.footprint(geometry)?;
            let placed = ccs
                .place(geometry.pitch, ccs::MAIN_ALIGNMENT, self.origin.x, self.origin.y)
                .ok_or(ScanoutError::Unsupported)?;
            return Ok((placed.main, placed.plane_offset(), bytes.max(ccs.fetch_end)));
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
        // A compressed view's main offset is already Linux's 16 KiB-aligned
        // one, with the x/y its AUX plane requires.
        if self.ccs.is_some() {
            return Ok((base, offset, bytes));
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
    /// `PLANE_AUX_DIST` of this view's compressed layout in GGTT
    /// ([`ccs::CcsPlacement::aux_dist`] at the view's origin); `None`
    /// without an AUX plane.
    pub(crate) fn ccs_aux_dist(self, geometry: Geometry) -> Option<u32> {
        let ccs = self.ccs.filter(|c| c.aux.is_some())?;
        ccs.place(geometry.pitch, ccs::MAIN_ALIGNMENT, self.origin.x, self.origin.y)?.aux_dist()
    }
    /// The GGTT alignment a surface of this view needs: `fallback`, or a
    /// compressed view's 16 KiB (`tgl_plane_min_alignment`), so its main
    /// offsets stay 16 KiB aligned in GGTT.
    pub(crate) fn surface_alignment(self, fallback: u32) -> u32 {
        if self.ccs.is_some() {
            fallback.max(ccs::MAIN_ALIGNMENT)
        } else {
            fallback
        }
    }
    pub(crate) fn tiled(self) -> u32 {
        if let Some(ccs) = self.ccs {
            return ccs.ccs.plane_ctl();
        }
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

/// `PLANE_SURF` alignment of a display page table in GGTT
/// (skl_universal_plane.c::tgl_plane_min_alignment: "PLANE_SURF GGTT -> DPT
/// alignment", 512 x 4 KiB for linear-class X/Tile4 modifiers).
const DPT_ALIGNMENT: u32 = 512 * 4096;

/// The power-of-two remapped display page table of a display-20 X/Tile4
/// surface. Display 20 has no `PLANE_CHICKEN` no-DPT bit
/// (intel_dpt_common.c::intel_dpt_configure programs it on display 14
/// only), so intel_fb.c::intel_fb_uses_dpt holds for every non-linear
/// modifier (`HAS_DPT`, `enable_dpt` by default), and display >= 14 remaps
/// it to a power-of-two stride (`intel_fb_needs_pot_stride_remap`). Tile
/// row `r` starts at DPT entry `r * dst`, with `dst =
/// roundup_pow_of_two(max(width tiles, 8))`
/// (`plane_view_dst_stride_tiles`), and `PLANE_STRIDE` is the source stride
/// when it is the smaller (`plane_view_scanout_stride`). Only that case is
/// owned: `dst` is then Linux's for any framebuffer width up to the pitch,
/// and `PLANE_STRIDE` stays the source stride.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DptLayout {
    /// Source stride in tiles (`pitch / tile width bytes`).
    pub(crate) src: u32,
    /// Visible width in tiles (`plane_view_width_tiles` at origin zero).
    pub(crate) width: u32,
    /// Remapped DPT stride in entries.
    pub(crate) dst: u32,
    /// Tile rows (`plane_view_height_tiles` at origin zero).
    pub(crate) rows: u32,
}
impl DptLayout {
    /// The layout of `geometry` in `layout` at `origin`, returning the
    /// power-of-two DPT dimensions, source tile origin `(start_col, start_row)`,
    /// and sub-tile `PLANE_OFFSET`. `None` for a linear surface, invalid tiled
    /// geometry/bounds, or a source stride wider than `dst`.
    pub(crate) fn with_origin(
        geometry: Geometry,
        layout: Layout,
        origin: Viewport,
    ) -> Option<(Self, u32, u32, u32)> {
        Self::with_origin_for(geometry, layout, origin, false)
    }
    /// [`Self::with_origin`]; a compressed framebuffer (`ccs`) remaps at
    /// its whole source stride (`calc_plane_remap_info`: "The hardware
    /// automagically calculates the CCS AUX surface stride from the main
    /// surface stride", so `dst = roundup_pow_of_two(max(src, 8))`).
    pub(crate) fn with_origin_for(
        geometry: Geometry,
        layout: Layout,
        origin: Viewport,
        ccs: bool,
    ) -> Option<(Self, u32, u32, u32)> {
        let view = View {
            origin,
            layout,
            ..View::default()
        };
        if layout == Layout::Linear || view.footprint(geometry).is_err() {
            return None;
        }
        // intel_tile_width_bytes / intel_tile_height for plain X and Tile4.
        let (tile_bytes, tile_rows) = if layout == Layout::X {
            (512, 8)
        } else {
            (128, 32)
        };
        let tile_pixels = tile_bytes / 4;
        let start_col = origin.x / tile_pixels;
        let start_row = origin.y / tile_rows;
        let res_x = origin.x % tile_pixels;
        let res_y = origin.y % tile_rows;
        let src = geometry.pitch / tile_bytes;
        let width = (res_x + geometry.width).div_ceil(tile_pixels);
        let dst = if ccs { src } else { width }.max(8).next_power_of_two();
        let rows = (res_y + geometry.height).div_ceil(tile_rows);
        let plane_offset = (res_y << 16) | res_x;
        (src <= dst).then_some((
            Self {
                src,
                width,
                dst,
                rows,
            },
            start_col,
            start_row,
            plane_offset,
        ))
    }
    /// A display-20 flat-CCS (`_LNL_CCS`) view through its DPT, as Linux
    /// scans one out: the framebuffer's remapped view from origin zero
    /// (`intel_fb_needs_pot_stride_remap`, at the whole source stride for
    /// CCS, [`Self::with_origin_for`]) through the last row and column the
    /// view fetches, and the main surface at its DPT-aligned offset in that
    /// view with the rest in `PLANE_OFFSET` ([`ccs::CcsPlanes::place`] at
    /// the remapped stride with [`ccs::DPT_MAIN_ALIGNMENT`]; a CCS plane is
    /// never remapped to the view, `intel_plane_can_remap`). Returns the
    /// layout, `PLANE_SURF`'s byte offset into the table (`skl_surf_address`:
    /// the DPT offset >> 9) and `PLANE_OFFSET`.
    pub(crate) fn ccs(
        geometry: Geometry,
        origin: Viewport,
        ccs: &ccs::CcsPlanes,
    ) -> Option<(Self, u32, u32)> {
        let whole = Geometry {
            width: origin.x.checked_add(geometry.width)?,
            height: origin.y.checked_add(geometry.height)?,
            pitch: geometry.pitch,
        };
        let (layout, ..) = Self::with_origin_for(whole, Layout::Tile4, Viewport::default(), true)?;
        let placed = ccs.place(layout.dst * 128, ccs::DPT_MAIN_ALIGNMENT, origin.x, origin.y)?;
        Some((layout, placed.main >> 9, placed.plane_offset()))
    }
    /// The layout of `geometry` in `layout`, or `None` for a linear surface,
    /// an invalid tiled geometry or a source stride wider than `dst`.
    pub(crate) fn new(geometry: Geometry, layout: Layout) -> Option<Self> {
        Self::with_origin(geometry, layout, Viewport::default()).map(|(layout, ..)| layout)
    }
    /// The DPT's bytes, page aligned.
    pub(crate) fn bytes(self) -> u64 {
        (u64::from(self.dst) * u64::from(self.rows) * 8).next_multiple_of(GTT_PAGE_SIZE)
    }
    /// The framebuffer page DPT entry `index` maps starting from source tile
    /// `(start_col, start_row)`, `None` for a padding entry
    /// (`xe_fb_pin.c::write_dpt_remapped` leaves them unwritten: "The DE ignores
    /// the PTEs for the padding tiles").
    pub(crate) fn source_at(self, index: u32, start_col: u32, start_row: u32) -> Option<u32> {
        let (row, column) = (index / self.dst, index % self.dst);
        (row < self.rows && column < self.width)
            .then_some((start_row + row) * self.src + (start_col + column))
    }
    /// The framebuffer page DPT entry `index` maps at origin zero, `None` for
    /// a padding entry.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn source(self, index: u32) -> Option<u32> {
        self.source_at(index, 0, 0)
    }
}

struct Surface {
    object: Arc<GemObject>,
    /// The display page table a display-20 tiled surface is fetched through;
    /// `offset`/`pages` then map the table, not the framebuffer.
    _dpt: Option<Arc<GemObject>>,
    /// Sub-tile `PLANE_OFFSET` when `_dpt` is present (whole-tile offsets are
    /// folded directly into the DPT entries starting at `offset`); a
    /// compressed view's is Linux's x/y ([`DptLayout::ccs`]).
    dpt_plane_offset: Option<u32>,
    /// `PLANE_SURF`'s byte offset into the table: 0, or a compressed view's
    /// DPT-aligned main offset >> 9 ([`DptLayout::ccs`]).
    dpt_surf: u32,
    offset: u32,
    pages: u32,
    geometry: Geometry,
    view: View,
}
#[derive(Clone, Copy)]
struct Pending {
    id: SurfaceId,
    offset: u32,
    /// The PLANE_SURF value: `offset`, with `PLANE_SURF_DECRYPT` for a
    /// decrypted protected surface.
    surf: u32,
    geometry: Geometry,
    view: View,
    plane_offset: u32,
    ticket: u64,
    frame: u32,
    deadline: u64,
    deferred: bool,
    /// Whether the plane CSC was black before this arm: a staged DSB arm
    /// that is cancelled unarmed leaves it so.
    black_before: bool,
}
#[derive(Clone, Copy)]
struct Target {
    offset: u32,
    geometry: Geometry,
    view: View,
    plane_offset: u32,
    /// `check_protection` for the surface's object.
    protection: crate::intel_gpu_gt::media::pxp::PlaneProtection,
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
    vram_scanout: bool,
    free: Vec<(u32, u32)>,
    surfaces: BTreeMap<SurfaceId, Surface>,
    next_id: u64,
    current: Option<SurfaceId>,
    console_surface: u32,
    console_geometry: Option<Geometry>,
    expected_surface: u32,
    /// The latched PLANE_SURF value (`expected_surface`, with
    /// `PLANE_SURF_DECRYPT` for a decrypted protected surface).
    expected_surf: u32,
    /// The plane CSC was last programmed black (`force_black`).
    black: bool,
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
            vram_scanout: false,
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
            expected_surf: initial_surface,
            black: false,
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
        (self.console_ctl & !(CTL_FORMAT_MASK | CTL_TILED_MASK | CTL_DECOMPRESSION_MASK))
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
            vram_scanout: false,
            free: alloc::vec![],
            surfaces: BTreeMap::new(),
            next_id: 1,
            current: None,
            console_surface: console,
            console_geometry: Some(geometry),
            expected_surface: console,
            expected_surf: console,
            black: false,
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
                protection: Default::default(),
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

    pub fn with_vram_scanout(mut self, allow: bool) -> Self {
        self.vram_scanout = allow;
        self
    }

    /// A foreign import is fetched from its mapped attachment's pages
    /// (another card's memory or BAR), only on an integrated display and
    /// only once `intel_gpu_prime::pin_for_scanout` pinned and mapped it.
    fn scanout_backing_ok(&self, object: &GemObject) -> bool {
        // i915_fb_pin.c intel_fb_pin_to_ggtt: with HAS_LMEM (DG1) a
        // framebuffer is migrated to LMEM_0 before the display pins it. This
        // owner migrates nothing, so DG1 scans out VRAM objects only.
        if self.gen12_family == Some(crate::intel_gpu_gt::Gen12Platform::Dg1) {
            return object.scanout()
                && !object.is_userptr()
                && !object.restore_pending()
                && self.vram_scanout
                && object.is_vram();
        }
        object.scanout()
            && !object.is_userptr()
            && !object.restore_pending()
            && ((self.vram_scanout && object.is_vram())
                || object.is_wc()
                || (!self.vram_scanout && object.is_imported() && object.import_mapped()))
    }

    fn encode_surface_pte(
        &self,
        object: &GemObject,
        phys: u64,
    ) -> Result<u64, crate::intel_gpu_gtt::GttError> {
        if object.is_vram() {
            crate::intel_gpu_gtt::encode_display_vram_pte(self.format, phys, self.pat)
        } else {
            crate::intel_gpu_gtt::encode_display_pte(self.format, phys, self.pat)
        }
    }
    /// Whether `layout` is scanned out at this owner's surface address:
    /// directly (linear, or the display-14/Gen12 no-DPT chickens), or on
    /// display 20 through the DPT [`Self::prepare_dpt`] builds for every
    /// tiled surface.
    fn tiling_addressable(&self, layout: Layout) -> bool {
        if layout == Layout::Linear {
            return true;
        }
        // intel_dpt_common.c::intel_dpt_configure sets the PLANE_CHICKEN
        // no-DPT bit on display 14 only: a display-20 tiled primary is
        // fetched through its owned DPT.
        if self.format == PteFormat::Xe2 {
            return true;
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
    fn pipe_index(&self) -> u8 {
        self.pipe as u8
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
        if !self.scanout_backing_ok(&object) {
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
            && (!self.tiling_addressable(view.layout)
                || (self.format == PteFormat::Gen12 && self.gen12_family.is_none()))
        {
            return Err(ScanoutError::Unsupported);
        }
        if !self.scanout_backing_ok(&object) {
            return Err(ScanoutError::Unsupported);
        }
        if self.format == PteFormat::Xe2 && view.layout != Layout::Linear {
            return self.prepare_dpt(object, geometry, view);
        }
        self.prepare_object_view(object, geometry, view)
    }

    /// Map a display-20 X/Tile4 surface through an owned display page
    /// table ([`DptLayout`]), supporting tiled panning (`view.origin`) by
    /// folding whole-tile offsets into the remapped DPT entries and keeping
    /// the sub-tile residual in `PLANE_OFFSET`.
    fn prepare_dpt(
        &mut self,
        object: Arc<GemObject>,
        geometry: Geometry,
        view: View,
    ) -> Result<SurfaceId, ScanoutError> {
        self.ready()?;
        if view.input != InputFormat::Xrgb8888 {
            return Err(ScanoutError::Unsupported);
        }
        let (_, _, extent) = view.footprint(geometry)?;
        if extent > object.size() {
            return Err(ScanoutError::Bounds);
        }
        let (layout, start_col, start_row, plane_offset, dpt_surf) = match view.ccs {
            Some(ccs) => {
                let (layout, surf, plane_offset) = DptLayout::ccs(geometry, view.origin, &ccs)
                    .ok_or(ScanoutError::Unsupported)?;
                (layout, 0, 0, plane_offset, surf)
            }
            None => {
                let (layout, col, row, plane_offset) =
                    DptLayout::with_origin_for(geometry, view.layout, view.origin, false)
                        .ok_or(ScanoutError::Unsupported)?;
                (layout, col, row, plane_offset, 0)
            }
        };
        if !object.idle(false) {
            return Err(ScanoutError::Busy);
        }
        let frames: Vec<u64> = object
            .pages()
            .take((extent / GTT_PAGE_SIZE) as usize)
            .collect();
        if frames.len() as u64 != extent / GTT_PAGE_SIZE {
            return Err(ScanoutError::Bounds);
        }
        let mut entries = alloc::vec![0u8; layout.bytes() as usize];
        for index in 0..layout.dst * layout.rows {
            let Some(page) = layout.source_at(index, start_col, start_row) else {
                continue;
            };
            let phys = *frames.get(page as usize).ok_or(ScanoutError::Bounds)?;
            let pte = self
                .encode_surface_pte(&object, phys)
                .map_err(|_| ScanoutError::Bounds)?;
            entries[index as usize * 8..index as usize * 8 + 8].copy_from_slice(&pte.to_le_bytes());
        }
        let gem = GemState::new();
        let handle = gem
            .create_placed(layout.bytes(), None, Placement::SystemWc, |_, _| Ok(()))
            .map_err(|_| ScanoutError::Busy)?;
        let table = gem.object(handle).map_err(|_| ScanoutError::Busy)?;
        gem.close(handle).map_err(|_| ScanoutError::Busy)?;
        table
            .write(0, &entries)
            .map_err(|_| ScanoutError::Unavailable)?;
        let pages = (layout.bytes() / GTT_PAGE_SIZE) as u32;
        let ptes: Vec<u64> = table
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
                let aligned = start.next_multiple_of(DPT_ALIGNMENT);
                let prefix = (aligned - start) / 4096;
                (n >= pages + prefix).then_some((slot, aligned, prefix))
            })
            .ok_or(ScanoutError::Busy)?;
        if !object.publish_for_device() || !table.publish_for_device() {
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
        // Ownership of the framebuffer and its table precedes the first
        // hardware-visible write, including on readback failure.
        self.surfaces.insert(
            id,
            Surface {
                object,
                _dpt: Some(table),
                dpt_plane_offset: Some(plane_offset),
                dpt_surf,
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
            || !self.latched_expected()
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
            .map(|phys| self.encode_surface_pte(&object, phys))
            .collect::<Result<_, _>>()
            .map_err(|_| ScanoutError::Bounds)?;
        if ptes.len() != pages as usize {
            return Err(ScanoutError::Bounds);
        }
        // A compressed view's framebuffer is pinned 16 KiB aligned
        // (`intel_plane_fb_min_alignment`), so its main offsets stay aligned.
        let alignment = view.surface_alignment(self.alignment);
        let (slot, offset, prefix) = self
            .free
            .iter()
            .enumerate()
            .find_map(|(slot, &(start, n))| {
                let aligned = (start + alignment - 1) & !(alignment - 1);
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
                _dpt: None,
                dpt_plane_offset: None,
                dpt_surf: 0,
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

        // A compressed view's decompression bits and AUX distance are part
        // of what it armed (skl_program_plane_noarm / _arm); any other view
        // owns neither.
        let decompression = if view.ccs.is_some() {
            CTL_DECOMPRESSION_MASK
        } else {
            0
        };
        let aux_dist = view.ccs_aux_dist(geometry).unwrap_or(0);
        ctl != u32::MAX
            && ctl & !(ALLOWED_CTL | CTL_TILED_MASK | decompression) == 0
            && ctl
                & (PLANE_CTL_ENABLE
                    | CTL_FORMAT_MASK
                    | CTL_TILED_MASK
                    | CTL_RGB_ORDER
                    | CTL_DECOMPRESSION_MASK)
                == PLANE_CTL_ENABLE | view.input.control() | view.tiled()
            && ctl == self.control(view)
            && self.tiling_addressable(view.layout)
            && self.io().read32(self.plane() + PLANE_STRIDE_OFFSET) == stride
            && self.io().read32(self.plane() + PLANE_SIZE_OFFSET)
                == ((geometry.height - 1) << 16) | (geometry.width - 1)
            && self.io().read32(self.plane() + AUX_DIST_OFFSET) == aux_dist
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
        // Display 11 (Gen11) has no PIPEDMC fault: GEN12_PIPEDMC_FAULT
        // (bit 25) is TGL+ (display 12+); the display-11 mask is only the
        // cursor/plane faults, which collapse into PLANE_FAULT here.
        match self.format {
            PteFormat::Xe2 => FIFO_UNDERRUN | PLANE_FAULT | (1 << 18),
            PteFormat::XeLpg => FIFO_UNDERRUN | PLANE_FAULT | (1 << 25) | (1 << 18) | (1 << 24),
            PteFormat::Gen12 => FIFO_UNDERRUN | PLANE_FAULT | (1 << 25),
            PteFormat::Gen8 => FIFO_UNDERRUN | PLANE_FAULT,
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
        // check_protection, at each commit: the object's key now.
        let protection =
            crate::intel_gpu_gt::media::pxp::plane_protection(surface.object.pxp_key());
        self.arm_target(
            id,
            Target {
                offset,
                geometry,
                view: surface.view,
                plane_offset,
                protection,
            },
            ticket,
            now,
            false,
        )
    }

    /// Retain a pending target and fresh primary completion status without
    /// writing SURF. The exclusive KMS owner emits the returned arm in its
    /// source-qualified DSB safe window, after color arm registers.
    ///
    /// `check_protection` runs here too, at each commit: a protected
    /// surface whose key is current is armed with `PLANE_SURF_DECRYPT`, and
    /// one whose key is stale (or that has no PXP) scans out black, with
    /// `icl_plane_csc_load_black`'s twelve zeroes and the plane CSC enable
    /// of `glk_plane_color_ctl` ahead of the SURF write that latches them.
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
        let (base, plane_offset) = if let Some(dpt_offset) = surface.dpt_plane_offset {
            (surface.dpt_surf, dpt_offset)
        } else {
            let (base, plane_offset, _) = surface
                .view
                .footprint_aligned(surface.geometry, self.alignment)?;
            (base, plane_offset)
        };
        let view = surface.view;
        // intel_atomic_prepare_plane_clear_colors: the CC plane's native
        // value, read by the CPU before the commit's plane programming.
        let ccval = match view.ccs.and_then(|c| c.cc_native_offset()) {
            Some(at) => {
                let mut native = [0u8; 8];
                surface
                    .object
                    .read(at, &mut native)
                    .map_err(|_| ScanoutError::Unavailable)?;
                Some(u64::from_le_bytes(native))
            }
            None => None,
        };
        let (offset, geometry) = (surface.offset + base, surface.geometry);
        let protection =
            crate::intel_gpu_gt::media::pxp::plane_protection(surface.object.pxp_key());
        self.arm_target(
            id,
            Target {
                offset,
                geometry,
                view,
                plane_offset,
                protection,
            },
            ticket,
            now,
            true,
        )?;
        let surf = if protection.decrypt {
            offset | PLANE_SURF_DECRYPT
        } else {
            offset
        };
        let mut registers = alloc::vec![
            (self.plane() + PLANE_OFFSET_OFFSET, plane_offset),
            (self.plane() + PLANE_SURF_OFFSET, surf),
        ];
        if protection.force_black {
            // A stale protected surface: the all-zero plane CSC, enabled.
            let color = self.io().read32(self.plane() + COLOR_CTL_OFFSET);
            let mut black: Vec<(u64, u32)> = PLANE_CSC_BLACK
                .iter()
                .map(|reg| (self.plane() + reg, 0))
                .collect();
            black.push((
                self.plane() + COLOR_CTL_OFFSET,
                color | PLANE_COLOR_CSC_ENABLE,
            ));
            // After PLANE_OFFSET, before the SURF write that latches them.
            let tail = registers.split_off(1);
            registers.extend(black);
            registers.extend(tail);
            self.black = true;
        } else if self.black {
            // A plane left black by a stale protected surface gets its CSC
            // back with this arm.
            let color = self.io().read32(self.plane() + COLOR_CTL_OFFSET);
            registers.insert(
                0,
                (
                    self.plane() + COLOR_CTL_OFFSET,
                    color & !PLANE_COLOR_CSC_ENABLE,
                ),
            );
            self.black = false;
        }
        if self.io().read32(self.plane() + PLANE_STRIDE_OFFSET) != view.stride(geometry)
            || self.io().read32(self.plane() + PLANE_CTL_OFFSET) != self.control(view)
        {
            registers.insert(
                0,
                (self.plane() + PLANE_STRIDE_OFFSET, view.stride(geometry)),
            );
            registers.insert(2, (self.plane() + PLANE_CTL_OFFSET, self.control(view)));
        }
        // skl_program_plane_noarm's PLANE_CC_VAL and PLANE_AUX_DIST (display
        // 14) precede the arm; a view leaving a compressed one clears the
        // AUX distance it no longer fetches.
        let noarm = match view.ccs {
            Some(ccs) => {
                ccs.noarm_registers_at(self.pipe_index(), ccval, view.ccs_aux_dist(geometry))
            }
            None if self.io().read32(self.plane() + AUX_DIST_OFFSET) != 0 => alloc::vec![
                (self.plane() + AUX_DIST_OFFSET, 0),
                (self.plane() + AUX_OFFSET_OFFSET, 0),
            ],
            None => alloc::vec::Vec::new(),
        };
        for (index, register) in noarm.into_iter().enumerate() {
            registers.insert(index, register);
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
        if !self.latched_expected()
            || self.io().read32(self.plane() + PLANE_OFFSET_OFFSET) != self.expected_offset
            || !self.geometry_matches(
                self.console_geometry.ok_or(ScanoutError::Unsupported)?,
                self.expected_view,
            )
        {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        // The black CSC (or its removal) was never armed either.
        if let Some(pending) = self.pending.take() {
            self.black = pending.black_before;
        }
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
                protection: Default::default(),
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
        if !self.latched_expected() {
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
            protection,
        } = target;
        let surf = if protection.decrypt {
            offset | PLANE_SURF_DECRYPT
        } else {
            offset
        };
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
            surf,
            geometry,
            view,
            plane_offset,
            ticket,
            frame,
            deadline: now.saturating_add(FLIP_TIMEOUT_NS),
            deferred,
            black_before: self.black,
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
        // force_black (icl_plane_csc_load_black, glk_plane_color_ctl): a
        // protected surface whose key is stale scans out through an all-zero
        // plane CSC. Both are armed by the SURF write below.
        if protection.force_black || self.black {
            if protection.force_black {
                for reg in PLANE_CSC_BLACK {
                    self.io().write32(self.plane() + reg, 0);
                }
            }
            let color = self.io().read32(self.plane() + COLOR_CTL_OFFSET);
            let want = if protection.force_black {
                color | PLANE_COLOR_CSC_ENABLE
            } else {
                color & !PLANE_COLOR_CSC_ENABLE
            };
            self.io().write32(self.plane() + COLOR_CTL_OFFSET, want);
            self.black = protection.force_black;
            if color == u32::MAX || self.io().read32(self.plane() + COLOR_CTL_OFFSET) != want {
                self.failed = true;
                return Err(ScanoutError::Unavailable);
            }
        }
        self.io().write32(self.plane() + PLANE_SURF_OFFSET, surf);
        if self.io().read32(self.plane() + PLANE_SURF_OFFSET) != surf {
            self.failed = true;
            return Err(ScanoutError::Unavailable);
        }
        Ok(())
    }

    /// SURFLIVE reports a surface whose PLANE_SURF value is `surf` at
    /// address `offset` (with or without the decrypt bit).
    fn live_is(&self, live: u32, offset: u32, surf: u32) -> bool {
        live == offset || live == surf
    }

    /// PLANE_SURF and SURFLIVE hold the latched surface.
    fn latched_expected(&self) -> bool {
        let live = self.io().read32(self.plane() + SURFLIVE_OFFSET);
        self.io().read32(self.plane() + PLANE_SURF_OFFSET) == self.expected_surf
            && self.live_is(live, self.expected_surface, self.expected_surf)
    }

    /// Whether the plane CSC was last programmed black (a stale protected
    /// surface, `force_black`), or is staged so in a DSB arm.
    pub(crate) fn forced_black(&self) -> bool {
        self.black
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
            && self.live_is(live, pending.offset, pending.surf)
            && status & PRIMARY_FLIP_DONE != 0
        {
            if self.io().read32(self.plane() + PLANE_SURF_OFFSET) != pending.surf
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
            self.expected_surf = pending.surf;
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
            || !self.live_is(live, self.expected_surface, self.expected_surf)
            || self.io().read32(self.plane() + PLANE_SURF_OFFSET) != self.expected_surf
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

#[path = "intel_gpu_ccs_scanout.rs"]
pub(crate) mod ccs;
