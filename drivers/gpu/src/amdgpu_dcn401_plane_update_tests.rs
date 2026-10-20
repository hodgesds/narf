use super::*;
use crate::amdgpu_dcn401_otg::tests::engine;
use crate::amdgpu_dcn401_spl::{Rect, Rotation};
use narf_kernel_test::{kernel_test_in, TestResult};

fn placed(format: SurfaceFormat, src: Rect, dst: Rect) -> SurfaceRequest {
    SurfaceRequest {
        pipe: 3,
        width: 1280,
        height: 720,
        format,
        odm: SplitPipes::NONE,
        mpc: SplitPipes::NONE,
        plane: Some(PlaneLayout {
            src,
            dst,
            stream_width: 1920,
            stream_height: 1080,
            ycbcr420: false,
            rotation: Rotation::R0,
            blend: Blend::default_for(format),
            underlay: false,
        }),
        surface: PlaneSurface::LINEAR,
    }
}

/// det_surface_update's classification of what amdgpu_dm hands DC for a
/// kept plane: a flip is fast; a move, the per-pixel or plane alpha, the
/// pitch and the YCbCr color space are medium; a new source or destination
/// size, format (but not its X/A twin), bytes per pixel, rotation, tiling
/// or DCC are full; a plane added, removed or recreated (zpos) is full.
fn dcn401_plane_update_types_follow_dc() -> TestResult {
    use UpdateType::{Fast, Full, Med};
    let src = Rect::new(0, 0, 1280, 720);
    let dst = Rect::new(100, 100, 640, 360);
    let base = placed(SurfaceFormat::Argb8888, src, dst);
    let with = |f: &dyn Fn(&mut SurfaceRequest)| {
        let mut r = base;
        f(&mut r);
        r
    };
    let layout = |f: &dyn Fn(&mut PlaneLayout)| {
        with(&|r: &mut SurfaceRequest| {
            let mut l = r.plane.unwrap();
            f(&mut l);
            r.plane = Some(l);
        })
    };
    let cases: [(SurfaceRequest, UpdateType); 16] = [
        (base, Fast),
        // A moved destination, or source origin: position_change.
        (layout(&|l| l.dst.x = 400), Med),
        (layout(&|l| l.src.x = 8), Med),
        // A resized destination or source: scaling_change.
        (layout(&|l| l.dst.width = 1280), Full),
        (layout(&|l| l.src.height = 700), Full),
        // Plane alpha and per-pixel alpha.
        (layout(&|l| l.blend.global_alpha = Some(0x80)), Med),
        (layout(&|l| l.blend.per_pixel_alpha = false), Med),
        // Pre-multiplied is not part of DC's update check.
        (layout(&|l| l.blend.premultiplied = false), Fast),
        // X and A variants are one DC format; RGB565 is another bpp.
        (with(&|r| r.format = SurfaceFormat::Xrgb8888), Fast),
        (with(&|r| r.format = SurfaceFormat::Abgr8888), Full),
        (with(&|r| r.format = SurfaceFormat::Rgb565), Full),
        // Any new ROTATION_ANGLE: rotation_change.
        (layout(&|l| l.rotation = Rotation::R180), Full),
        (layout(&|l| l.rotation = Rotation::R90), Full),
        (layout(&|l| l.rotation = Rotation::R270), Full),
        // A new pitch (wider surface, same rectangles): plane_size_change.
        (with(&|r| r.width = 1920), Med),
        (
            with(&|r| r.surface.tiling.swizzle = crate::amdgpu_dcn401_otg::Swizzle::S64K2D),
            Full,
        ),
    ];
    for (k, (new, want)) in cases.iter().enumerate() {
        if plane_update_type(base, *new) != *want {
            let _ = k;
            return TestResult::Fail("plane update type");
        }
    }
    // The YCbCr color space of a 4:2:0 plane is medium.
    let video = with(&|r| r.format = SurfaceFormat::Nv12);
    let bt601 = SurfaceRequest {
        surface: PlaneSurface {
            color: YuvColor::Bt601,
            ..video.surface
        },
        ..video
    };
    if plane_update_type(video, bt601) != Med || plane_update_type(base, video) != Full {
        return TestResult::Fail("color space and video format");
    }
    // 90 to 270 keeps the scan direction but not the angle.
    let turned = layout(&|l| l.rotation = Rotation::R90);
    if plane_update_type(turned, layout(&|l| l.rotation = Rotation::R270)) != Full
        || plane_update_type(turned, turned) != Fast
    {
        return TestResult::Fail("rotation 90/270 update type");
    }
    // Stream level: a plane count change or a recreated plane is full.
    let moved = layout(&|l| l.dst.x = 400);
    if planes_update_type(&[base], &[moved], false) != Med
        || planes_update_type(&[base], &[base, moved], false) != Full
        || planes_update_type(&[base, moved], &[base], false) != Full
        || planes_update_type(&[base], &[base], true) != Full
        || planes_update_type(&[base], &[layout(&|l| l.underlay = true)], false) != Full
    {
        return TestResult::Fail("stream update type");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-plane-update",
    dcn401_plane_update_types_follow_dc
);

/// The register writes `f` makes to the MPCC tree selectors (low nibble)
/// and MPCC_MODE (MPCC_CONTROL's low two bits) of every pipe, in order.
fn tree_writes(
    e: &mut Engine<crate::amdgpu_dcn401_otg::tests::Fake>,
    f: impl FnOnce(&mut Engine<crate::amdgpu_dcn401_otg::tests::Fake>),
) -> Vec<(u64, u32)> {
    let l = e.layout;
    let mut regs = Vec::new();
    for q in 0..4u8 {
        for r in [TOP, BOTTOM, OPP_ID, UPDATE_LOCK] {
            regs.push((l.mpcc(q, r), 0xf));
        }
        regs.push((l.out_mux(q), 0xf));
        regs.push((l.mpcc(q, MPCC_CONTROL), 3));
    }
    e.io.writes.clear();
    f(e);
    e.io.writes
        .iter()
        .filter_map(|&(at, v)| {
            regs.iter()
                .find(|&&(r, _)| r == at)
                .map(|&(_, mask)| (at, v & mask))
        })
        .collect()
}

/// mpc1_remove_mpcc and mpc1_insert_plane as dcn20_update_mpcc runs them
/// on a full update, write for write: removing the top MPCC moves the
/// OPP's OUT_MUX to the one below; removing the bottom one makes the MPCC
/// above it pass its top layer through; removing a middle one links its
/// neighbours; every removed MPCC's muxes and update lock go to 0xf;
/// inserting at the bottom makes the old bottom blend over the new one.
fn dcn401_plane_update_mpc_tree_follows_mpc1() -> TestResult {
    let mut e = engine();
    let l = e.layout;
    let w = |q: u8, r: u64, v: u32| (l.mpcc(q, r), v);
    let c = |q: u8, v: u32| (l.mpcc(q, MPCC_CONTROL), v);
    let mux = |o: u8, v: u32| (l.out_mux(o), v);
    // OPP 0's tree, top first: 3 over 1 over 0.
    let mut t = MpcTree {
        opp: 0,
        list: alloc::vec![3, 1, 0],
    };
    let off = |q: u8| {
        [
            w(q, TOP, 0xf),
            w(q, BOTTOM, 0xf),
            w(q, OPP_ID, 0xf),
            w(q, UPDATE_LOCK, 0xf),
        ]
    };
    let got = tree_writes(&mut e, |e| e.mpc_remove(&mut t, 1).unwrap());
    let mut want = alloc::vec![w(3, BOTTOM, 0)];
    want.extend(off(1));
    if got != want || t.list != [3, 0] {
        return TestResult::Fail("remove a middle MPCC");
    }
    let got = tree_writes(&mut e, |e| e.mpc_remove(&mut t, 0).unwrap());
    let mut want = alloc::vec![w(3, BOTTOM, 0xf), c(3, MODE_PASSTHROUGH)];
    want.extend(off(0));
    if got != want || t.list != [3] {
        return TestResult::Fail("remove the bottom MPCC");
    }
    let got = tree_writes(&mut e, |e| e.mpc_insert_bottom(&mut t, 2).unwrap());
    let want = [
        w(2, BOTTOM, 0xf),
        c(2, MODE_TOP_ONLY),
        w(2, TOP, 2),
        w(2, OPP_ID, 0),
        w(2, UPDATE_LOCK, 0),
        w(3, BOTTOM, 2),
        c(3, MODE_TOP_BOT),
    ];
    if got != want || t.list != [3, 2] {
        return TestResult::Fail("insert at the bottom");
    }
    let got = tree_writes(&mut e, |e| e.mpc_remove(&mut t, 3).unwrap());
    let mut want = alloc::vec![mux(0, 2)];
    want.extend(off(3));
    if got != want || t.list != [2] {
        return TestResult::Fail("remove the top MPCC");
    }
    let got = tree_writes(&mut e, |e| {
        e.mpc_remove(&mut t, 2).unwrap();
        e.mpc_insert_bottom(&mut t, 2).unwrap();
    });
    let mut want = alloc::vec![mux(0, 0xf)];
    want.extend(off(2));
    want.extend([
        w(2, BOTTOM, 0xf),
        c(2, MODE_TOP_ONLY),
        w(2, TOP, 2),
        w(2, OPP_ID, 0),
        w(2, UPDATE_LOCK, 0),
        mux(0, 2),
    ]);
    if got != want || t.list != [2] {
        return TestResult::Fail("re-insert the only MPCC");
    }
    // An MPCC in no tree is left alone.
    if !tree_writes(&mut e, |e| e.mpc_remove(&mut t, 1).unwrap()).is_empty() {
        return TestResult::Fail("remove an absent MPCC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-plane-update",
    dcn401_plane_update_mpc_tree_follows_mpc1
);
