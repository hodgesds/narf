//! Compressed primary layouts behind `narf.intel.ccs=1`.
//!
//! Pinned source: Linux 7.4-rc4 `include/uapi/drm/drm_fourcc.h`
//! (`I915_FORMAT_MOD_4_TILED_MTL_RC_CCS`, `_MTL_MC_CCS`, `_MTL_RC_CCS_CC`,
//! `_LNL_CCS`), `i915/display/intel_fb.c` (`intel_modifiers`,
//! `plane_has_modifier`, `gen12_ccs_aux_stride`, `intel_fb_stride_alignment`,
//! `intel_framebuffer_init`'s CCS plane checks), `skl_universal_plane.c`
//! (`skl_plane_ctl_tiling`, `skl_plane_aux_dist`, `skl_program_plane_noarm`:
//! `PLANE_CC_VAL` and `PLANE_AUX_DIST`), `intel_display.c`
//! (`intel_atomic_prepare_plane_clear_colors`: the clear colour at offset 16
//! of the CC plane), `intel_display_device.h` (`HAS_AUX_DIST`: display 9..12,
//! ADL-P and Meteor Lake), `i915_driver.c` / `xe_display.c` (`has_auxccs`),
//! and `skl_universal_plane_regs.h`.
//!
//! Display 14 (Meteor/Arrow Lake) decompresses AuxCCS: the main Tile4
//! surface plus a packed AUX plane in the same object (`PLANE_AUX_DIST`, the
//! GGTT distance from the main surface), and with `_RC_CCS_CC` a clear-colour
//! plane whose native value goes to `PLANE_CC_VAL`. Only the i915 personality
//! offers it: xe's `has_auxccs` is Alder Lake-P alone. Display 20+ (Lunar,
//! Panther, Wildcat Lake) has flat CCS: `_LNL_CCS` is a single Tile4 plane
//! whose compression comes from the BO's PAT index (`XE2_COMP_EN`) and whose
//! decompression is `PLANE_CTL` alone, with no AUX plane or distance; Nova
//! Lake-S (display 35) and discrete parts are not admitted here.
//!
//! A panned view is placed as `skl_check_plane_surface` places it
//! ([`CcsPlanes::place`]): `skl_check_ccs_aux_surface` puts the AUX plane at
//! the 4 KiB AUX tile under the source position, then
//! `skl_check_main_surface` steps the main surface's aligned offset
//! (`tgl_plane_min_alignment`: 16 KiB in GGTT, 2 MiB through a DPT) back
//! until its x/y equal the AUX plane's, with `intel_fb.c`'s
//! `intel_compute_aligned_offset`, `intel_adjust_tile_offset`,
//! `intel_fb_offset_to_xy` and `intel_fb_plane_get_subsampling` (AUX 2 x 32).
//! `PLANE_SURF` is the main offset, `PLANE_OFFSET` its x/y and
//! `PLANE_AUX_DIST` the AUX offset minus the main one (`skl_plane_aux_dist`).
//! Display 20's flat CCS has no AUX plane: its main offset is taken in the
//! framebuffer's remapped DPT view, which a CCS plane never narrows to the
//! viewport (`intel_plane_can_remap`).

/// The strict default-off option.
pub const BOOT_OPTION: &str = "narf.intel.ccs";

/// Whether the boot command line carries exactly `narf.intel.ccs=1`.
pub fn opted_in() -> bool {
    crate::intel_gpu_gt::boot_opt_in(narf_boot::args(), BOOT_OPTION)
}

/// `fourcc_mod_code(INTEL, n)`.
const fn intel_mod(n: u64) -> u64 {
    (1 << 56) | n
}
pub const I915_FORMAT_MOD_4_TILED_MTL_RC_CCS: u64 = intel_mod(13);
pub const I915_FORMAT_MOD_4_TILED_MTL_MC_CCS: u64 = intel_mod(14);
pub const I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC: u64 = intel_mod(15);
pub const I915_FORMAT_MOD_4_TILED_LNL_CCS: u64 = intel_mod(16);

/// `PLANE_CTL_TILED_4`, `PLANE_CTL_RENDER_DECOMPRESSION_ENABLE`,
/// `PLANE_CTL_CLEAR_COLOR_DISABLE` (TGL+), `PLANE_CTL_MEDIA_DECOMPRESSION_ENABLE`.
pub const PLANE_CTL_TILED_4: u32 = 5 << 10;
pub const PLANE_CTL_RENDER_DECOMPRESSION_ENABLE: u32 = 1 << 15;
pub const PLANE_CTL_CLEAR_COLOR_DISABLE: u32 = 1 << 13;
pub const PLANE_CTL_MEDIA_DECOMPRESSION_ENABLE: u32 = 1 << 4;

/// The primary plane's `PLANE_CC_VAL(dw)` and `PLANE_AUX_DIST` /
/// `PLANE_AUX_OFFSET` on `pipe`.
pub const fn plane_cc_val(pipe: u8, dw: u8) -> u64 {
    0x701b4 + 0x1000 * pipe as u64 + 4 * dw as u64
}
pub const fn plane_aux_dist(pipe: u8) -> u64 {
    0x701c0 + 0x1000 * pipe as u64
}
pub const fn plane_aux_offset(pipe: u8) -> u64 {
    0x701c4 + 0x1000 * pipe as u64
}

/// A compressed layout this driver admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ccs {
    /// `_4_TILED_MTL_RC_CCS`: render compression, AUX plane, no clear colour.
    MtlRc,
    /// `_4_TILED_MTL_MC_CCS`: media compression, AUX plane.
    MtlMc,
    /// `_4_TILED_MTL_RC_CCS_CC`: render compression, AUX and clear colour.
    MtlRcCc,
    /// `_4_TILED_LNL_CCS`: flat CCS, compression from the BO's PAT.
    Xe2,
}

/// Why a compressed framebuffer is refused. Nothing was created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CcsRefusal {
    /// `narf.intel.ccs=1` is absent.
    Disabled,
    /// Not a modifier of this display (`plane_has_modifier`: the MTL
    /// modifiers are display 14.00 only and need AuxCCS, which xe lacks;
    /// `_LNL_CCS` is display 20+ integrated).
    Modifier,
    /// Only XRGB8888 / XBGR8888 primaries (`gen12_ccs_formats`, which also
    /// lists ARGB/ABGR; only the opaque ones are owned here).
    Format,
    /// A plane's handle, pitch or offset breaks `intel_framebuffer_init`'s
    /// CCS rules.
    Planes,
    /// The planes run past the object.
    Bounds,
}

/// One admitted compressed framebuffer's layout in its object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CcsPlanes {
    pub ccs: Ccs,
    /// The AUX plane's byte offset and pitch (AuxCCS only).
    pub aux: Option<(u32, u32)>,
    /// The clear-colour plane's byte offset (`_RC_CCS_CC` only).
    pub cc: Option<u32>,
    /// The end of the last plane the display fetches (main, or AUX), which
    /// the scanout mapping must cover.
    pub fetch_end: u64,
}

impl Ccs {
    /// `intel_modifiers` / `plane_has_modifier` for `modifier` on display
    /// `display_ver` under the given personality.
    pub fn from_modifier(modifier: u64, display_ver: u16, xe: bool) -> Result<Self, CcsRefusal> {
        match modifier {
            I915_FORMAT_MOD_4_TILED_MTL_RC_CCS if display_ver == 14 && !xe => Ok(Self::MtlRc),
            I915_FORMAT_MOD_4_TILED_MTL_MC_CCS if display_ver == 14 && !xe => Ok(Self::MtlMc),
            I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC if display_ver == 14 && !xe => Ok(Self::MtlRcCc),
            I915_FORMAT_MOD_4_TILED_LNL_CCS if (20..35).contains(&display_ver) => Ok(Self::Xe2),
            _ => Err(CcsRefusal::Modifier),
        }
    }

    /// Whether `modifier` is one of the compressed modifiers here.
    pub const fn is_ccs_modifier(modifier: u64) -> bool {
        matches!(
            modifier,
            I915_FORMAT_MOD_4_TILED_MTL_RC_CCS
                | I915_FORMAT_MOD_4_TILED_MTL_MC_CCS
                | I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC
                | I915_FORMAT_MOD_4_TILED_LNL_CCS
        )
    }

    /// `skl_plane_ctl_tiling`.
    pub const fn plane_ctl(self) -> u32 {
        match self {
            Self::MtlRc => {
                PLANE_CTL_TILED_4
                    | PLANE_CTL_RENDER_DECOMPRESSION_ENABLE
                    | PLANE_CTL_CLEAR_COLOR_DISABLE
            }
            Self::MtlRcCc | Self::Xe2 => PLANE_CTL_TILED_4 | PLANE_CTL_RENDER_DECOMPRESSION_ENABLE,
            Self::MtlMc => PLANE_CTL_TILED_4 | PLANE_CTL_MEDIA_DECOMPRESSION_ENABLE,
        }
    }

    /// The number of framebuffer planes the modifier's format takes.
    pub const fn planes(self) -> usize {
        match self {
            Self::MtlRc | Self::MtlMc => 2,
            Self::MtlRcCc => 3,
            Self::Xe2 => 1,
        }
    }
}

/// The compressed modifiers IN_FORMATS lists for display `display_ver`
/// (the i915 personality's on display 14, flat CCS on display 20/30), in
/// `intel_modifiers` order.
pub fn advertised(display_ver: u16) -> &'static [u64] {
    match display_ver {
        14 => &[
            I915_FORMAT_MOD_4_TILED_MTL_MC_CCS,
            I915_FORMAT_MOD_4_TILED_MTL_RC_CCS,
            I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC,
        ],
        20..=34 => &[I915_FORMAT_MOD_4_TILED_LNL_CCS],
        _ => &[],
    }
}

/// `gen12_ccs_aux_stride`: one 64-byte AUX line per 512 bytes of main
/// pitch (four Tile4 widths).
pub const fn gen12_ccs_aux_stride(main_pitch: u32) -> u32 {
    main_pitch / 512 * 64
}

/// `intel_framebuffer_init`'s CCS checks for an XRGB8888/XBGR8888 primary
/// of `height` rows in an object of `size` bytes: every plane in the main
/// plane's object (`handles`), the main pitch a multiple of four Tile4
/// widths (`intel_fb_stride_alignment` for Gen12 CCS), the AUX pitch
/// `gen12_ccs_aux_stride` with a page-aligned AUX surface, the clear-colour
/// plane 64-byte aligned with pitch 0, unused planes empty, and every plane
/// inside the object.
pub fn check_planes(
    ccs: Ccs,
    fourcc: u32,
    height: u32,
    handles: [u32; 4],
    pitches: [u32; 4],
    offsets: [u32; 4],
    size: u64,
) -> Result<CcsPlanes, CcsRefusal> {
    // DRM_FORMAT_XRGB8888 / DRM_FORMAT_XBGR8888.
    if !matches!(fourcc, 0x3432_5258 | 0x3432_4258) {
        return Err(CcsRefusal::Format);
    }
    let n = ccs.planes();
    if offsets[0] != 0
        || (1..n).any(|i| handles[i] != handles[0])
        || (n..4).any(|i| handles[i] != 0 || pitches[i] != 0 || offsets[i] != 0)
    {
        return Err(CcsRefusal::Planes);
    }
    let main_rows = u64::from(height.div_ceil(32) * 32);
    let main_end = u64::from(pitches[0]) * main_rows;
    if ccs == Ccs::Xe2 {
        return if pitches[0] % 128 != 0 || pitches[0] == 0 {
            Err(CcsRefusal::Planes)
        } else if main_end > size {
            Err(CcsRefusal::Bounds)
        } else {
            Ok(CcsPlanes {
                ccs,
                aux: None,
                cc: None,
                fetch_end: main_end,
            })
        };
    }
    if pitches[0] == 0
        || pitches[0] % 512 != 0
        || pitches[1] != gen12_ccs_aux_stride(pitches[0])
        || offsets[1] % 4096 != 0
        || u64::from(offsets[1]) < main_end
    {
        return Err(CcsRefusal::Planes);
    }
    // The AUX plane (`intel_fb_plane_get_subsampling`: vsub 32) has one
    // line per 32 main lines and is itself tiled in 64-byte x 64-line tiles
    // (`intel_tile_width_bytes` 64 for a Gen12 CCS plane, `intel_tile_height`
    // 4096 / 64), so its size is the AUX pitch over whole AUX tile rows.
    let aux_lines = u64::from(height.div_ceil(32)).div_ceil(64) * 64;
    let aux_end = u64::from(offsets[1]) + u64::from(pitches[1]) * aux_lines;
    let cc = if ccs == Ccs::MtlRcCc {
        if pitches[2] != 0 || offsets[2] % 64 != 0 || u64::from(offsets[2]) < aux_end {
            return Err(CcsRefusal::Planes);
        }
        Some(offsets[2])
    } else {
        None
    };
    let end = cc.map_or(aux_end, |cc| u64::from(cc) + 64);
    if end > size {
        return Err(CcsRefusal::Bounds);
    }
    Ok(CcsPlanes {
        ccs,
        aux: Some((offsets[1], pitches[1])),
        cc,
        fetch_end: aux_end,
    })
}

impl CcsPlanes {
    /// `skl_plane_aux_dist` on display 12+: the AUX surface's distance from
    /// the main surface (both page aligned, no stride field); 0 without an
    /// AUX plane. Flat CCS programs no `PLANE_AUX_DIST` (`HAS_AUX_DIST`).
    pub fn aux_dist(&self) -> Option<u32> {
        self.aux.map(|(offset, _)| offset)
    }

    /// `PLANE_CC_VAL` from the clear-colour plane's 8-byte native value at
    /// offset 16 (`intel_atomic_prepare_plane_clear_colors`): low, high.
    pub fn cc_val(native: u64) -> [u32; 2] {
        [native as u32, (native >> 32) as u32]
    }

    /// The clear colour's native value position in the object
    /// (`intel_atomic_prepare_plane_clear_colors`: offset 16 of the CC plane).
    pub fn cc_native_offset(&self) -> Option<u64> {
        self.cc.map(|cc| u64::from(cc) + 16)
    }

    /// [`Self::program`]'s writes as a register list (`PLANE_CC_VAL` low and
    /// high, `PLANE_AUX_DIST`, `PLANE_AUX_OFFSET`) for a DSB arm of the
    /// primary of `pipe`, scanned out from origin zero.
    pub fn noarm_registers(&self, pipe: u8, ccval: Option<u64>) -> alloc::vec::Vec<(u64, u32)> {
        self.noarm_registers_at(pipe, ccval, self.aux_dist())
    }

    /// [`Self::noarm_registers`] with the AUX distance of the view's
    /// placement ([`CcsPlacement::aux_dist`]).
    pub fn noarm_registers_at(
        &self,
        pipe: u8,
        ccval: Option<u64>,
        aux_dist: Option<u32>,
    ) -> alloc::vec::Vec<(u64, u32)> {
        let mut out = alloc::vec::Vec::new();
        if let (Some(_), Some(native)) = (self.cc, ccval) {
            let [lo, hi] = Self::cc_val(native);
            out.push((plane_cc_val(pipe, 0), lo));
            out.push((plane_cc_val(pipe, 1), hi));
        }
        if let Some(dist) = aux_dist.filter(|_| self.aux.is_some()) {
            out.push((plane_aux_dist(pipe), dist));
            out.push((plane_aux_offset(pipe), 0));
        }
        out
    }

    /// `skl_check_plane_surface` for a compressed primary scanned out from
    /// (`src_x`, `src_y`): `skl_check_ccs_aux_surface` places the AUX plane
    /// at the 4 KiB AUX tile holding the source position (its x/y in main
    /// pixels within that tile), then `skl_check_main_surface` takes the
    /// main surface's aligned offset (`skl_calc_main_surface_offset`, kept
    /// at or below the AUX one) and steps it back by `alignment` until its
    /// x/y equal the AUX plane's (`skl_check_main_ccs_coordinates`, which
    /// may step the AUX plane back by 4 KiB tiles too), since "CCS AUX
    /// surface doesn't have its own x/y offsets". `mapping_pitch` is the
    /// main surface's row pitch in the view (the framebuffer pitch in GGTT,
    /// or the remapped DPT stride on display 20) and `alignment` the main
    /// surface's (`tgl_plane_min_alignment`: [`MAIN_ALIGNMENT`] in GGTT,
    /// [`DPT_MAIN_ALIGNMENT`] through a DPT). `None` where Linux finds no
    /// offset ("unable to find suitable display surface offset due to
    /// CCS") or the x/y would not fit `PLANE_OFFSET`.
    pub fn place(
        &self,
        mapping_pitch: u32,
        alignment: u32,
        src_x: u32,
        src_y: u32,
    ) -> Option<CcsPlacement> {
        let main_pitch_tiles = u64::from(mapping_pitch) / (MAIN_TILE_W * 4);
        let alignment = u64::from(alignment);
        if main_pitch_tiles == 0 || alignment == 0 || alignment % TILE_SIZE != 0 {
            return None;
        }
        let main = Tiled {
            tile_w: MAIN_TILE_W,
            tile_h: MAIN_TILE_H,
            pitch_tiles: main_pitch_tiles,
        };
        let (src_x, src_y) = (u64::from(src_x), u64::from(src_y));
        // skl_check_ccs_aux_surface.
        let aux = match self.aux {
            Some((offset, pitch)) => {
                let tiled = Tiled {
                    tile_w: AUX_TILE_W,
                    tile_h: AUX_TILE_H,
                    pitch_tiles: u64::from(pitch) / AUX_TILE_W,
                };
                if tiled.pitch_tiles == 0 {
                    return None;
                }
                // intel_fb_offset_to_xy: the AUX plane's normal-view x/y.
                let (mut nx, mut ny) = (0, 0);
                tiled.adjust(&mut nx, &mut ny, u64::from(offset), 0);
                let mut x = src_x / AUX_HSUB + nx;
                let mut y = src_y / AUX_VSUB + ny;
                let at = tiled.aligned_offset(&mut x, &mut y, AUX_ALIGNMENT);
                Some(AuxState {
                    tiled,
                    x: x * AUX_HSUB + src_x % AUX_HSUB,
                    y: y * AUX_VSUB + src_y % AUX_VSUB,
                    offset: at,
                })
            }
            None => None,
        };
        // skl_check_main_surface / skl_calc_main_surface_offset.
        let (mut x, mut y) = (src_x, src_y);
        let mut offset = main.aligned_offset(&mut x, &mut y, alignment);
        let aux = match aux {
            Some(mut aux) => {
                if offset > aux.offset {
                    let to = aux.offset & !(alignment - 1);
                    offset = main.adjust(&mut x, &mut y, offset, to);
                }
                while !aux.matches(x, y, offset) {
                    if offset == 0 {
                        break;
                    }
                    offset = main.adjust(&mut x, &mut y, offset, offset - alignment);
                }
                if x != aux.x || y != aux.y {
                    return None;
                }
                Some(u32::try_from(aux.offset).ok()?)
            }
            None => None,
        };
        if x > 0xffff || y > 0xffff {
            return None;
        }
        Some(CcsPlacement {
            main: u32::try_from(offset).ok()?,
            x: x as u32,
            y: y as u32,
            aux,
        })
    }

    /// `skl_program_plane_noarm`'s compressed registers for the primary of
    /// `pipe`, before its `PLANE_CTL`/`PLANE_SURF` arm: `PLANE_CC_VAL` for a
    /// clear-colour layout, `PLANE_AUX_DIST` on display 14, `PLANE_AUX_OFFSET`
    /// 0. `ccval` is the CC plane's native value. Returns the `PLANE_CTL`
    /// tiling and decompression bits the arm ORs in.
    pub fn program<M: crate::intel_gpu_aux::MmioWindow + ?Sized>(
        &self,
        regs: &M,
        pipe: u8,
        ccval: Option<u64>,
    ) -> u32 {
        for (register, value) in self.noarm_registers(pipe, ccval) {
            regs.write32(register, value);
        }
        self.ccs.plane_ctl()
    }
}

/// `intel_tile_size`.
const TILE_SIZE: u64 = 4096;
/// The Tile4 main plane of an XRGB8888 primary in pixels:
/// `intel_tile_width_bytes` 128 over cpp 4, `intel_tile_height` 4096 / 128.
const MAIN_TILE_W: u64 = 32;
const MAIN_TILE_H: u64 = 32;
/// The Gen12 CCS AUX plane in its own units (cpp 1):
/// `intel_tile_width_bytes` 64, `intel_tile_height` 4096 / 64.
const AUX_TILE_W: u64 = 64;
const AUX_TILE_H: u64 = 64;
/// `intel_fb_plane_get_subsampling` for the AUX plane of a
/// `gen12_ccs_formats` XRGB8888/XBGR8888 primary: `block_w` 2 over 1 times
/// the format's hsub 1, and vsub 32.
const AUX_HSUB: u64 = 2;
const AUX_VSUB: u64 = 32;
/// `tgl_plane_min_alignment` for the AUX plane: "AUX_DIST needs only 4K
/// alignment".
const AUX_ALIGNMENT: u64 = 4096;
/// `tgl_plane_min_alignment` for a CCS main surface in GGTT: "Align to at
/// least 4x1 main surface tiles (16K) to match 64B of AUX".
pub const MAIN_ALIGNMENT: u32 = 16 * 1024;
/// The same through a display page table (`mult` 512: "PLANE_SURF GGTT ->
/// DPT alignment").
pub const DPT_MAIN_ALIGNMENT: u32 = 512 * 4096;

/// Where [`CcsPlanes::place`] puts a compressed view's planes, as byte
/// offsets into the view's mapping: the main surface's aligned offset
/// (`PLANE_SURF`), its x/y (`PLANE_OFFSET`) and the AUX surface's offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CcsPlacement {
    pub main: u32,
    pub x: u32,
    pub y: u32,
    pub aux: Option<u32>,
}

impl CcsPlacement {
    /// `PLANE_OFFSET`: y in the high half, x in the low one.
    pub fn plane_offset(&self) -> u32 {
        (self.y << 16) | self.x
    }

    /// `skl_plane_aux_dist` on display 12+: the AUX surface's distance from
    /// the main one (`skl_calc_main_surface_offset` keeps it non-negative).
    pub fn aux_dist(&self) -> Option<u32> {
        self.aux.map(|aux| aux - self.main)
    }
}

/// One tiled colour plane's geometry in a view: tile size in the plane's
/// units and the mapping pitch in tiles.
#[derive(Clone, Copy)]
struct Tiled {
    tile_w: u64,
    tile_h: u64,
    pitch_tiles: u64,
}

impl Tiled {
    /// `intel_adjust_tile_offset`: move the tiles between `old` and `new`
    /// into x/y, then minimize x.
    fn adjust(self, x: &mut u64, y: &mut u64, old: u64, new: u64) -> u64 {
        let tiles = (old - new) / TILE_SIZE;
        *y += tiles / self.pitch_tiles * self.tile_h;
        *x += tiles % self.pitch_tiles * self.tile_w;
        let pitch_pixels = self.pitch_tiles * self.tile_w;
        *y += *x / pitch_pixels * self.tile_h;
        *x %= pitch_pixels;
        new
    }

    /// `intel_compute_aligned_offset` for a tiled plane: the offset of the
    /// tile holding x/y, rounded down to `alignment`, the rest in x/y.
    fn aligned_offset(self, x: &mut u64, y: &mut u64, alignment: u64) -> u64 {
        let tile_rows = *y / self.tile_h;
        *y %= self.tile_h;
        let tiles = *x / self.tile_w;
        *x %= self.tile_w;
        let offset = (tile_rows * self.pitch_tiles + tiles) * TILE_SIZE;
        self.adjust(x, y, offset, offset - offset % alignment)
    }
}

/// The AUX plane's view offset and x/y in main pixels.
#[derive(Clone, Copy)]
struct AuxState {
    tiled: Tiled,
    x: u64,
    y: u64,
    offset: u64,
}

impl AuxState {
    /// `skl_check_main_ccs_coordinates`: step the AUX plane back by 4 KiB
    /// tiles while it stays at or above the main surface and its y at or
    /// above the main one, until both x/y match; only a match is kept.
    fn matches(&mut self, main_x: u64, main_y: u64, main_offset: u64) -> bool {
        let (mut ax, mut ay, mut at) = (self.x, self.y, self.offset);
        while at >= main_offset && ay <= main_y {
            if ax == main_x && ay == main_y {
                break;
            }
            if at == 0 {
                break;
            }
            let mut x = ax / AUX_HSUB;
            let mut y = ay / AUX_VSUB;
            at = self.tiled.adjust(&mut x, &mut y, at, at - AUX_ALIGNMENT);
            ax = x * AUX_HSUB + ax % AUX_HSUB;
            ay = y * AUX_VSUB + ay % AUX_VSUB;
        }
        if ax != main_x || ay != main_y {
            return false;
        }
        (self.x, self.y, self.offset) = (ax, ay, at);
        true
    }
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_ccs_scanout_tests.rs"]
mod tests;
