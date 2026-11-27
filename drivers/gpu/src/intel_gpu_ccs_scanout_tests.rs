//! Compressed primary fixtures: the modifiers' plane rules and the plane
//! registers of an AuxCCS (display 14) and a flat-CCS (display 20)
//! scanout, written out from drm_fourcc.h, intel_fb.c and
//! skl_universal_plane*.c.

extern crate alloc;

use super::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Regs {
    map: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
}
impl crate::intel_gpu_aux::MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        *self.map.borrow().get(&off).unwrap_or(&0)
    }
    fn write32(&self, off: u64, v: u32) {
        self.writes.borrow_mut().push((off, v));
        self.map.borrow_mut().insert(off, v);
    }
}

const XRGB8888: u32 = 0x3432_5258;
const ARGB8888: u32 = 0x3432_5241;
const OBJECT_SIZE: u64 = 9 << 20;

/// 1920x1080 XRGB8888 in Tile4: pitch 7680 (15 x 512), 34 tile rows of 32
/// lines, so the main surface ends at 7680 * 1088 = 0x7f8000; the AUX pitch
/// is DIV_ROUND_UP(7680, 4 * 128) * 64 = 960, and its ceil(1080 / 32) = 34
/// lines round up to one 64-line AUX tile row (64-byte x 64-line CCS tiles):
/// 960 * 64 = 0xf000 bytes, ending at 0x807000, where the 64-byte
/// clear-colour plane starts. The object is 9 MiB.
fn mtl_planes(ccs: Ccs) -> Result<CcsPlanes, CcsRefusal> {
    let cc = if ccs == Ccs::MtlRcCc {
        (1, 0x80_7000)
    } else {
        (0, 0)
    };
    check_planes(
        ccs,
        XRGB8888,
        1080,
        [7, 7, cc.0 * 7, 0],
        [7680, 960, 0, 0],
        [0, 0x7f_8000, cc.1, 0],
        OBJECT_SIZE,
    )
}

fn smoke_ccs_modifiers_and_plane_rules_follow_intel_fb() -> TestResult {
    // fourcc_mod_code(INTEL, 13..16).
    if I915_FORMAT_MOD_4_TILED_MTL_RC_CCS != 0x0100_0000_0000_000d
        || I915_FORMAT_MOD_4_TILED_MTL_MC_CCS != 0x0100_0000_0000_000e
        || I915_FORMAT_MOD_4_TILED_MTL_RC_CCS_CC != 0x0100_0000_0000_000f
        || I915_FORMAT_MOD_4_TILED_LNL_CCS != 0x0100_0000_0000_0010
    {
        return TestResult::Fail("modifier values must be drm_fourcc.h's");
    }
    // plane_has_modifier: MTL AuxCCS on display 14 under i915 only (xe's
    // has_auxccs is ADL-P), LNL flat CCS on display 20 and 30, not 35.
    if Ccs::from_modifier(I915_FORMAT_MOD_4_TILED_MTL_RC_CCS, 14, false) != Ok(Ccs::MtlRc)
        || Ccs::from_modifier(I915_FORMAT_MOD_4_TILED_MTL_RC_CCS, 14, true)
            != Err(CcsRefusal::Modifier)
        || Ccs::from_modifier(I915_FORMAT_MOD_4_TILED_MTL_RC_CCS, 20, false)
            != Err(CcsRefusal::Modifier)
        || Ccs::from_modifier(I915_FORMAT_MOD_4_TILED_LNL_CCS, 20, true) != Ok(Ccs::Xe2)
        || Ccs::from_modifier(I915_FORMAT_MOD_4_TILED_LNL_CCS, 30, false) != Ok(Ccs::Xe2)
        || Ccs::from_modifier(I915_FORMAT_MOD_4_TILED_LNL_CCS, 14, false)
            != Err(CcsRefusal::Modifier)
        || Ccs::from_modifier(I915_FORMAT_MOD_4_TILED_LNL_CCS, 35, true)
            != Err(CcsRefusal::Modifier)
    {
        return TestResult::Fail("each modifier must belong to its display only");
    }
    let rc = match mtl_planes(Ccs::MtlRc) {
        Ok(p) => p,
        Err(_) => {
            return TestResult::Fail("a Linux-shaped MTL RC CCS framebuffer must be admitted")
        }
    };
    if rc.aux != Some((0x7f_8000, 960)) || rc.cc.is_some() {
        return TestResult::Fail("the AUX plane is plane 1 at its pitch");
    }
    if mtl_planes(Ccs::MtlRcCc).map(|p| (p.cc, p.fetch_end)) != Ok((Some(0x80_7000), 0x80_7000)) {
        return TestResult::Fail("the clear-colour plane is plane 2");
    }
    let refuse = |handles, pitches, offsets, size| {
        check_planes(Ccs::MtlRc, XRGB8888, 1080, handles, pitches, offsets, size).err()
    };
    if refuse(
        [7, 7, 0, 0],
        [7680, 896, 0, 0],
        [0, 0x7f_8000, 0, 0],
        OBJECT_SIZE,
    ) != Some(CcsRefusal::Planes)
        || refuse(
            [7, 8, 0, 0],
            [7680, 960, 0, 0],
            [0, 0x7f_8000, 0, 0],
            OBJECT_SIZE,
        ) != Some(CcsRefusal::Planes)
        || refuse(
            [7, 7, 0, 0],
            [7680, 960, 0, 0],
            [0, 0x7f_7000, 0, 0],
            OBJECT_SIZE,
        ) != Some(CcsRefusal::Planes)
        || refuse(
            [7, 7, 0, 0],
            [7168 + 128, 960, 0, 0],
            [0, 0x7f_8000, 0, 0],
            OBJECT_SIZE,
        ) != Some(CcsRefusal::Planes)
        || refuse(
            [7, 7, 0, 0],
            [7680, 960, 0, 0],
            [0, 0x7f_8000, 0, 0],
            0x80_6000,
        ) != Some(CcsRefusal::Bounds)
        || check_planes(
            Ccs::MtlRc,
            ARGB8888,
            1080,
            [7, 7, 0, 0],
            [7680, 960, 0, 0],
            [0, 0x7f_8000, 0, 0],
            OBJECT_SIZE,
        ) != Err(CcsRefusal::Format)
    {
        return TestResult::Fail("gen12_ccs_aux_stride, one object, no overlap, bounds, format");
    }
    // _RC_CCS_CC: the CC plane is 64-byte aligned past the AUX plane.
    if check_planes(
        Ccs::MtlRcCc,
        XRGB8888,
        1080,
        [7, 7, 7, 0],
        [7680, 960, 0, 0],
        [0, 0x7f_8000, 0x80_7010, 0],
        OBJECT_SIZE,
    ) != Err(CcsRefusal::Planes)
    {
        return TestResult::Fail("a misaligned clear-colour plane must be refused");
    }
    // _LNL_CCS: one plane, no AUX.
    let flat = check_planes(
        Ccs::Xe2,
        XRGB8888,
        1080,
        [7, 0, 0, 0],
        [7680, 0, 0, 0],
        [0, 0, 0, 0],
        OBJECT_SIZE,
    );
    if flat.map(|p| (p.aux, p.cc)) != Ok((None, None))
        || check_planes(
            Ccs::Xe2,
            XRGB8888,
            1080,
            [7, 7, 0, 0],
            [7680, 960, 0, 0],
            [0, 0x7f_8000, 0, 0],
            OBJECT_SIZE,
        ) != Err(CcsRefusal::Planes)
    {
        return TestResult::Fail("flat CCS takes exactly one plane");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    smoke_ccs_modifiers_and_plane_rules_follow_intel_fb
);

/// The plane registers of a compressed scanout on Pipe B: display 14
/// `_RC_CCS_CC` writes `PLANE_CC_VAL` (from the CC plane's native value)
/// and `PLANE_AUX_DIST`; display 20 `_LNL_CCS` writes neither
/// (`HAS_AUX_DIST`), and both OR `skl_plane_ctl_tiling`'s bits into
/// `PLANE_CTL`.
fn smoke_ccs_and_xe2_scanout_plane_registers() -> TestResult {
    // skl_plane_ctl_tiling: TILED_4 (5 << 10), RENDER_DECOMPRESSION (bit 15),
    // CLEAR_COLOR_DISABLE (bit 13), MEDIA_DECOMPRESSION (bit 4).
    if Ccs::MtlRc.plane_ctl() != 0xb400
        || Ccs::MtlRcCc.plane_ctl() != 0x9400
        || Ccs::MtlMc.plane_ctl() != 0x1410
        || Ccs::Xe2.plane_ctl() != 0x9400
    {
        return TestResult::Fail("PLANE_CTL tiling bits must be skl_plane_ctl_tiling's");
    }
    let regs = Regs::default();
    let planes = mtl_planes(Ccs::MtlRcCc).expect("planes");
    let ctl = planes.program(&regs, 1, Some(0x1122_3344_5566_7788));
    // PLANE_CC_VAL(B, 0/1) = 0x711b4/0x711b8, PLANE_AUX_DIST(B) = 0x711c0
    // (the AUX surface 0x7f8000 past the main one), PLANE_AUX_OFFSET(B) 0.
    if ctl != 0x9400
        || *regs.writes.borrow()
            != [
                (0x711b4, 0x5566_7788),
                (0x711b8, 0x1122_3344),
                (0x711c0, 0x7f_8000),
                (0x711c4, 0),
            ]
    {
        return TestResult::Fail("the AuxCCS scanout must program CC_VAL and AUX_DIST");
    }
    let flat_regs = Regs::default();
    let flat = check_planes(
        Ccs::Xe2,
        XRGB8888,
        1080,
        [7, 0, 0, 0],
        [7680, 0, 0, 0],
        [0, 0, 0, 0],
        OBJECT_SIZE,
    )
    .expect("flat");
    if flat.program(&flat_regs, 1, None) != 0x9400 || !flat_regs.writes.borrow().is_empty() {
        return TestResult::Fail("flat CCS decompresses through PLANE_CTL alone");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    smoke_ccs_and_xe2_scanout_plane_registers
);

/// The scanout view of a compressed framebuffer: a mapping that covers the
/// AUX plane, Linux's placement for a panned view (below), and on display
/// 20 the DPT remap at the whole source stride (`calc_plane_remap_info`
/// keeps `src_stride` for CCS before `plane_view_dst_stride_tiles` rounds it
/// to a power of two).
fn smoke_ccs_view_footprint_and_xe2_dpt_stride() -> TestResult {
    use crate::intel_gpu_scanout::{DptLayout, Geometry, Layout, View, Viewport};
    let planes = mtl_planes(Ccs::MtlRc).expect("planes");
    let geometry = Geometry {
        width: 1920,
        height: 1080,
        pitch: 7680,
    };
    let view = View {
        layout: Layout::Tile4,
        ccs: Some(planes),
        ..View::default()
    };
    let panned = View {
        origin: Viewport { x: 32, y: 0 },
        ..view
    };
    let linear = View {
        layout: Layout::Linear,
        ..panned
    };
    // Tile4 1080 lines -> 34 tile rows x 7680 = 0x7f8000; the AUX plane
    // ends at 0x807000. Panned by one Tile4 column the main surface stays
    // at offset 0 with x 32, as the AUX plane's x/y (32, 0) require.
    if view.footprint(geometry) != Ok((0, 0, 0x80_7000))
        || panned.footprint(geometry) != Ok((0, 0x20, 0x80_7000))
        || panned.footprint_aligned(geometry, 4096) != Ok((0, 0x20, 0x80_7000))
        || panned.ccs_aux_dist(geometry) != Some(0x7f_8000)
        || view.tiled() != 0xb400
        || linear.footprint(geometry) != Err(crate::intel_gpu_scanout::ScanoutError::Unsupported)
    {
        return TestResult::Fail("a CCS view maps its AUX plane at Linux's placement");
    }
    // 1024 visible pixels (32 Tile4 columns) of a 7680-byte (60-tile)
    // pitch: plain Tile4 remaps to roundup_pow_of_two(32) = 32 < 60 and is
    // not owned; CCS remaps at roundup_pow_of_two(60) = 64.
    let narrow = Geometry {
        width: 1024,
        height: 64,
        pitch: 7680,
    };
    let origin = Viewport::default();
    if DptLayout::with_origin(narrow, Layout::Tile4, origin).is_some()
        || DptLayout::with_origin_for(narrow, Layout::Tile4, origin, true)
            .map(|(l, ..)| (l.src, l.width, l.dst, l.rows))
            != Some((60, 32, 64, 2))
    {
        return TestResult::Fail("the CCS DPT keeps the source stride, rounded to a power of two");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    smoke_ccs_view_footprint_and_xe2_dpt_stride
);

/// `skl_check_plane_surface` for panned compressed views, worked from Linux
/// 7.4's `intel_compute_aligned_offset` / `intel_adjust_tile_offset`
/// arithmetic.
///
/// Display 14 (`_RC_CCS` 1920x1080 above, in GGTT): main pitch 7680 = 60
/// Tile4 tiles; the AUX plane at 0x7f8000 is AUX tile 2040 of a 960-byte
/// pitch (15 AUX tiles), normal-view x/y (0, 2040 / 15 * 64 = 8704). The
/// AUX tile is chosen first, then the main surface is stepped back 16 KiB
/// at a time until x/y match:
///
/// | pan        | AUX tile, x/y             | main offset, x/y   | AUX_DIST |
/// |------------|---------------------------|--------------------|----------|
/// | (160, 0)   | 0x7f9000, (32, 0)         | 0x4000, (32, 0)    | 0x7f5000 |
/// | (0, 40)    | 0x7f8000, (0, 40)         | 0, (0, 40)         | 0x7f8000 |
/// | (160, 40)  | 0x7f9000, (32, 40)        | 0x4000, (32, 40)   | 0x7f5000 |
/// | (33, 33)   | 0x7f8000, (33, 33)        | 0, (33, 33)        | 0x7f8000 |
///
/// At (0, 40) the main tile (row 1) is 0x3c000 with x/y (0, 8); the AUX y
/// 40 is below it, so every 16 KiB step back to offset 0 is needed.
///
/// Display 20 (`_LNL_CCS`, the same framebuffer through its DPT): the
/// remapped view keeps the 60-tile source stride rounded to 64 (8192-byte
/// mapping rows) and the main surface aligns to 2 MiB (512 DPT entries).
/// A 1024x64 view at (160, 300) covers 37 x 12 tiles from origin zero; the
/// main tile (9 * 64 + 5) * 4096 = 0x245000 rounds down to 0x200000, the
/// 69 tiles between move into x/y (160, 12 + 32 = 44): `PLANE_SURF` is
/// 0x200000 >> 9 = 0x1000 into the table and `PLANE_OFFSET` 0x2c00a0.
fn smoke_ccs_panned_views_take_linux_offsets() -> TestResult {
    use crate::intel_gpu_scanout::{DptLayout, Geometry, Layout, View, Viewport};
    let planes = mtl_planes(Ccs::MtlRc).expect("planes");
    let place = |x, y| planes.place(7680, MAIN_ALIGNMENT, x, y);
    let at = |main, x, y, aux| {
        Some(CcsPlacement {
            main,
            x,
            y,
            aux: Some(aux),
        })
    };
    if place(160, 0) != at(0x4000, 32, 0, 0x7f_9000)
        || place(0, 40) != at(0, 0, 40, 0x7f_8000)
        || place(160, 40) != at(0x4000, 32, 40, 0x7f_9000)
        || place(33, 33) != at(0, 33, 33, 0x7f_8000)
        || place(160, 0).and_then(|p| p.aux_dist()) != Some(0x7f_5000)
        || place(160, 40).map(|p| p.plane_offset()) != Some(0x0028_0020)
    {
        return TestResult::Fail("panned AuxCCS views must take Linux's main and AUX offsets");
    }
    let geometry = Geometry {
        width: 1024,
        height: 64,
        pitch: 7680,
    };
    let view = View {
        origin: Viewport { x: 160, y: 40 },
        layout: Layout::Tile4,
        ccs: Some(planes),
        ..View::default()
    };
    // The mapping covers main rows 0..ceil(104 / 32) * 32 = 128 (0xf0000
    // bytes) and the whole AUX plane (0x807000).
    if view.footprint(geometry) != Ok((0x4000, 0x0028_0020, 0x80_7000))
        || view.ccs_aux_dist(geometry) != Some(0x7f_5000)
        || view.surface_alignment(4096) != MAIN_ALIGNMENT
        || View::default().surface_alignment(4096) != 4096
    {
        return TestResult::Fail("the presenter view must carry the placement");
    }
    let flat = check_planes(
        Ccs::Xe2,
        XRGB8888,
        1080,
        [7, 0, 0, 0],
        [7680, 0, 0, 0],
        [0, 0, 0, 0],
        OBJECT_SIZE,
    )
    .expect("flat");
    let (layout, surf, offset) =
        DptLayout::ccs(geometry, Viewport { x: 160, y: 300 }, &flat).expect("flat CCS DPT");
    if (layout.src, layout.width, layout.dst, layout.rows) != (60, 37, 64, 12)
        || surf != 0x1000
        || offset != 0x002c_00a0
        || flat.place(8192, DPT_MAIN_ALIGNMENT, 160, 300)
            != Some(CcsPlacement {
                main: 0x20_0000,
                x: 160,
                y: 44,
                aux: None,
            })
    {
        return TestResult::Fail("a panned flat-CCS view must take Linux's DPT offset");
    }
    // Unpanned, the table and the plane start at origin zero as before.
    let whole = Geometry {
        width: 1920,
        height: 1080,
        pitch: 7680,
    };
    match DptLayout::ccs(whole, Viewport::default(), &flat) {
        Some((l, 0, 0)) if (l.src, l.width, l.dst, l.rows) == (60, 60, 64, 34) => {}
        _ => return TestResult::Fail("an unpanned flat-CCS view starts at entry 0"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout",
    smoke_ccs_panned_views_take_linux_offsets
);
