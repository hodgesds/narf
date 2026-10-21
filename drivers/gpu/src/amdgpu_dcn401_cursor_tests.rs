use super::*;
use crate::amdgpu_dcn401_otg::tests::engine;
use narf_kernel_test::{kernel_test_in, TestResult};

fn dcn401_cursor_placement_follows_dcn401_clipping() -> TestResult {
    let at = |x, y| placement(x, y, (64, 64), (1920, 1080), (100_000, 148_500));
    let visible = |x, y, hot_x, hot_y, dst| Placement {
        visible: true,
        x,
        y,
        hot_x,
        hot_y,
        dst_x_offset: dst,
    };
    // On screen: position as given; DST_X_OFFSET in reference clocks.
    if at(100, 50) != visible(100, 50, 0, 0, 67) {
        return TestResult::Fail("on-screen placement");
    }
    // Negative origins move into the hotspot (amdgpu_dm/dcn401 rule).
    if at(-10, -5) != visible(0, 0, 10, 5, 0) || at(-63, 0) != visible(0, 0, 63, 0, 0) {
        return TestResult::Fail("negative origin");
    }
    // Last visible pixels, then fully off screen on each side.
    if !at(1919, 1079).visible {
        return TestResult::Fail("bottom-right pixel hidden");
    }
    for (x, y) in [
        (-64, 0),
        (0, -64),
        (1920, 0),
        (0, 1080),
        (i32::MIN, i32::MAX),
    ] {
        if at(x, y).visible {
            return TestResult::Fail("off-screen cursor shown");
        }
    }
    if lines_per_chunk(64) != 3 || lines_per_chunk(32) != 4 || lines_per_chunk(1) != 4 {
        return TestResult::Fail("lines per chunk");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_placement_follows_dcn401_clipping
);

fn dcn401_cursor_requires_live_scanout_and_bounded_image() -> TestResult {
    let mut e = engine();
    let surfaces = Surfaces::new();
    let pixels = alloc::vec![0u32; 64 * 64];
    if surfaces.move_cursor(&mut e, 0, (0, 0)) != Err(Error::Invalid)
        || e.status.state != State::Ready
    {
        return TestResult::Fail("cursor move without cursor");
    }
    for (w, h, len) in [(0, 64, 0), (65, 1, 65), (64, 64, 64 * 64 - 1)] {
        if !matches!(validate_image(w, h, &pixels[..len]), Err(Error::Invalid)) {
            return TestResult::Fail("bad cursor image accepted");
        }
    }
    if validate_image(64, 64, &pixels).is_err() {
        return TestResult::Fail("64x64 rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_requires_live_scanout_and_bounded_image
);

/// Linux's cursor registers for every pipe of DCN4 streams
/// (tests/dcn401_cursor_position: amdgpu_dm_plane_get_cursor_position,
/// dcn401_set_cursor_position, resource_can_pipe_disable_cursor,
/// hubp401_cursor_set_position and dpp401_set_cursor_position built on the
/// host).
const VECTORS: &str = include_str!("../tests/dcn401_cursor_position/vectors.txt");

/// One vector's stream: the cursor's position and size, the clocks and
/// every pipe (in tree order, segment by segment, bottom first) with the
/// pipes above it.
struct Stream {
    at: (i32, i32),
    size: (u32, u32),
    clocks: (u32, u32),
    pipes: alloc::vec::Vec<(CursorPipe, alloc::vec::Vec<CursorPipe>)>,
}
fn parse_stream(input: &str) -> Option<Stream> {
    let v: alloc::vec::Vec<i64> = input
        .split_whitespace()
        .map(|t| t.parse().ok())
        .collect::<Option<_>>()?;
    let (head, rest) = v.split_at_checked(7)?;
    let n = usize::try_from(head[6]).ok()?;
    if rest.len() != n * 14 {
        return None;
    }
    let rows: alloc::vec::Vec<&[i64]> = rest.chunks(14).collect();
    let rect = |r: &[i64]| spl::Rect::new(r[0] as i32, r[1] as i32, r[2] as i32, r[3] as i32);
    let mut pipes: alloc::vec::Vec<CursorPipe> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| CursorPipe {
            pipe: i as u8,
            layer: r[1] as u8,
            recout: rect(&r[2..6]),
            viewport: rect(&r[6..10]),
            h_ratio: r[10] as u32,
            src: (r[11] as i32, r[12] as i32),
            // A plane's pipes in other ODM segments, and the slice widths
            // of its pipes in the segments before this one.
            odm: rows.iter().any(|o| o[1] == r[1] && o[0] != r[0]),
            prev_odm_width: rows
                .iter()
                .filter(|o| o[1] == r[1] && o[0] < r[0])
                .map(|o| o[13] as i32)
                .sum(),
            top: rows.get(i + 1).is_some_and(|o| o[0] == r[0]),
            bottom: i > 0 && rows[i - 1][0] == r[0],
        })
        .collect();
    let segs: alloc::vec::Vec<i64> = rows.iter().map(|r| r[0]).collect();
    let mut out = alloc::vec::Vec::new();
    for i in 0..pipes.len() {
        let above: alloc::vec::Vec<CursorPipe> = (i + 1..pipes.len())
            .take_while(|&j| segs[j] == segs[i])
            .map(|j| pipes[j])
            .collect();
        out.push((pipes[i], above));
    }
    pipes.clear();
    Some(Stream {
        at: (head[0] as i32, head[1] as i32),
        size: (head[2] as u32, head[3] as u32),
        clocks: (head[4] as u32, head[5] as u32),
        pipes: out,
    })
}

fn dcn401_cursor_matches_linux_vectors() -> TestResult {
    let mut checked = 0;
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("vector line");
        };
        let Some(s) = parse_stream(input) else {
            return TestResult::Fail("vector input");
        };
        let pos = dm_position(s.at.0, s.at.1);
        let mut got = alloc::string::String::new();
        for (k, (p, above)) in s.pipes.iter().enumerate() {
            let at = pipe_position(pos, p, above, s.size, s.clocks);
            let en = u32::from(at.visible);
            use core::fmt::Write;
            let _ = write!(
                got,
                "{}{en} {} {} {} {} {} {en}",
                if k == 0 { "" } else { " " },
                at.x,
                at.y,
                at.hot_x,
                at.hot_y,
                at.dst_x_offset
            );
        }
        if got != want {
            return TestResult::Fail("cursor registers differ from Linux");
        }
        checked += 1;
    }
    if checked < 1000 {
        return TestResult::Fail("too few cursor vectors");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_matches_linux_vectors
);

fn plane(
    pipe: u8,
    (odm, mpc): (SplitPipes, SplitPipes),
    (width, height): (u32, u32),
    layout: Option<(spl::Rect, (u32, u32), bool)>,
) -> SurfaceApplied {
    SurfaceApplied {
        request: SurfaceRequest {
            pipe,
            width,
            height,
            format: SurfaceFormat::Argb8888,
            odm,
            mpc,
            plane: layout.map(|(dst, (sw, sh), underlay)| PlaneLayout {
                src: spl::Rect::new(0, 0, width as i32, height as i32),
                dst,
                stream_width: sw,
                stream_height: sh,
                ycbcr420: false,
                rotation: spl::Rotation::R0,
                blend: Blend::default_for(SurfaceFormat::Argb8888),
                underlay,
            }),
            surface: PlaneSurface::LINEAR,
        },
        address: 0x8_0010_0000,
        pitch_bytes: width * 4,
        bytes: u64::from(width * 4 * height),
        chroma: None,
    }
}
/// The pipes `stream_cursor_pipes` derives from planes (through SPL) are
/// the ones the Linux vectors describe for the same configurations: the
/// stack's layers, each segment's tree bottom first with its top/bottom
/// neighbours, the ODM slice widths before each pipe, recouts, viewports
/// and ratios.
fn dcn401_cursor_pipes_follow_the_planes_as_dc_does() -> TestResult {
    let config = |name: &str| {
        let mut lines = VECTORS
            .lines()
            .skip_while(|l| l.trim() != alloc::format!("# {name}"));
        lines
            .nth(1)
            .and_then(|l| l.split_once(" = "))
            .and_then(|(i, _)| parse_stream(i))
    };
    // Pipe numbers aside (the vectors number pipes in tree order).
    let same = |got: &[(CursorPipe, alloc::vec::Vec<CursorPipe>)], want: &Stream| {
        let strip = |p: &CursorPipe| CursorPipe { pipe: 0, ..*p };
        got.len() == want.pipes.len()
            && got.iter().zip(&want.pipes).all(|((g, ga), (w, wa))| {
                strip(g) == strip(w)
                    && ga.len() == wa.len()
                    && ga.iter().zip(wa).all(|(a, b)| strip(a) == strip(b))
            })
    };
    let none = [None; MAX_OVERLAYS];
    let primary = plane(0, (SplitPipes::NONE, SplitPipes::NONE), (1920, 1080), None);
    // An unscaled overlay above the primary.
    let ov = plane(
        3,
        (SplitPipes::NONE, SplitPipes::NONE),
        (640, 360),
        Some((spl::Rect::new(100, 100, 640, 360), (1920, 1080), false)),
    );
    let Some(want) = config("overlay") else {
        return TestResult::Fail("overlay vectors");
    };
    let got = stream_cursor_pipes(primary, &[Some(ov), None, None]);
    if !same(&got, &want)
        || got
            .iter()
            .map(|(p, _)| p.pipe)
            .collect::<alloc::vec::Vec<_>>()
            != [0, 3]
    {
        return TestResult::Fail("overlay pipes");
    }
    // A 2:1 downscaled overlay.
    let down = SurfaceApplied {
        request: SurfaceRequest {
            plane: Some(PlaneLayout {
                dst: spl::Rect::new(200, 150, 640, 360),
                ..ov.request.plane.unwrap()
            }),
            width: 1280,
            height: 720,
            ..ov.request
        },
        ..ov
    };
    let down = SurfaceApplied {
        request: SurfaceRequest {
            plane: Some(PlaneLayout {
                src: spl::Rect::new(0, 0, 1280, 720),
                ..down.request.plane.unwrap()
            }),
            ..down.request
        },
        ..down
    };
    match config("overlay-down") {
        Some(want)
            if same(
                &stream_cursor_pipes(primary, &[Some(down), None, None]),
                &want,
            ) => {}
        _ => return TestResult::Fail("downscaled overlay pipes"),
    }
    // ODM 2:1 with an overlay straddling the slices: a tree per segment.
    let odm_primary = plane(
        0,
        (SplitPipes::one(1), SplitPipes::NONE),
        (3840, 2160),
        None,
    );
    let straddle = plane(
        2,
        (SplitPipes::one(3), SplitPipes::NONE),
        (400, 300),
        Some((spl::Rect::new(1800, 500, 400, 300), (3840, 2160), false)),
    );
    let got = stream_cursor_pipes(odm_primary, &[Some(straddle), None, None]);
    match config("odm2-overlay") {
        Some(want) if same(&got, &want) => {}
        _ => return TestResult::Fail("ODM overlay pipes"),
    }
    if got
        .iter()
        .map(|(p, _)| p.pipe)
        .collect::<alloc::vec::Vec<_>>()
        != [0, 2, 1, 3]
    {
        return TestResult::Fail("ODM tree order");
    }
    // MPC combine: the second slice below the first.
    let mpc_primary = plane(
        0,
        (SplitPipes::NONE, SplitPipes::one(3)),
        (1920, 1080),
        None,
    );
    let got = stream_cursor_pipes(mpc_primary, &none);
    match config("mpc2") {
        Some(want) if same(&got, &want) => {}
        _ => return TestResult::Fail("MPC slice pipes"),
    }
    if got
        .iter()
        .map(|(p, _)| p.pipe)
        .collect::<alloc::vec::Vec<_>>()
        != [3, 0]
    {
        return TestResult::Fail("MPC tree order");
    }
    // An underlay below the primary: the lowest layer.
    let under = plane(
        2,
        (SplitPipes::NONE, SplitPipes::NONE),
        (800, 600),
        Some((spl::Rect::new(300, 200, 800, 600), (1920, 1080), true)),
    );
    match config("underlay") {
        Some(want)
            if same(
                &stream_cursor_pipes(primary, &[Some(under), None, None]),
                &want,
            ) => {}
        _ => return TestResult::Fail("underlay pipes"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_pipes_follow_the_planes_as_dc_does
);

/// The cursor over an overlay on an ODM 2:1 stream: attributes and
/// position go to every pipe of the stream (both segments' primary and
/// overlay pipes) inside both segments' cursor locks, each lock taken
/// before any cursor write and released after the last; the pipes the
/// cursor misses are written disabled.
fn dcn401_cursor_programs_every_pipe_under_each_segment_lock() -> TestResult {
    let mut e = engine();
    let l = e.layout;
    let odm_primary = plane(
        0,
        (SplitPipes::one(1), SplitPipes::NONE),
        (3840, 2160),
        None,
    );
    let straddle = plane(
        2,
        (SplitPipes::one(3), SplitPipes::NONE),
        (400, 300),
        Some((spl::Rect::new(1800, 500, 400, 300), (3840, 2160), false)),
    );
    e.status.surfaces[0] = Some(odm_primary);
    let a = CursorApplied {
        pipe: 0,
        address: 0x8_00f0_0000,
        width: 64,
        height: 64,
        x: 1890,
        y: 600,
        visible: false,
        shown: 0,
        degamma: false,
    };
    let clocks = (50_000, 594_000);
    let segments = placements(a, odm_primary, &[Some(straddle), None, None], clocks);
    let a = shown(a, &segments);
    // Linux (tests/dcn401_cursor_position "odm2-overlay", 1890 600 64x64):
    // every pipe shows its part, the right segment's with the hotspot.
    let want = [
        (0u8, 1890u32, 600u32, 0u32, 159u32),
        (2, 90, 100, 0, 7),
        (1, 0, 600, 30, 0),
        (3, 0, 100, 30, 0),
    ];
    if segments.len() != 4
        || segments
            .iter()
            .zip(want)
            .any(|(&(p, at), (q, x, y, hot, dst))| {
                (p, at.visible, at.x, at.y, at.hot_x, at.dst_x_offset) != (q, true, x, y, hot, dst)
            })
        || a.shown != 0xf
    {
        return TestResult::Fail("placements on every pipe");
    }
    e.io.writes.clear();
    if e.program_cursor(a, &segments).is_err() || e.verify_cursor(a, &segments).is_err() {
        return TestResult::Fail("program");
    }
    let lock = |o: u64| l.mpc_base + (0x2c5 + o * 5) * 4;
    let cursor_regs: alloc::vec::Vec<u64> = (0..4)
        .flat_map(|p| [l.hubp(p, 0x67d), l.hubp(p, 0x679)])
        .collect();
    let w = &e.io.writes;
    let first = w.iter().position(|&(at, _)| cursor_regs.contains(&at));
    let last = w.iter().rposition(|&(at, _)| cursor_regs.contains(&at));
    let taken: alloc::vec::Vec<usize> = [0, 1]
        .iter()
        .filter_map(|&o| w.iter().position(|&(at, v)| at == lock(o) && v & 1 == 1))
        .collect();
    let released: alloc::vec::Vec<usize> = [0, 1]
        .iter()
        .filter_map(|&o| w.iter().rposition(|&(at, v)| at == lock(o) && v & 1 == 0))
        .collect();
    let (Some(first), Some(last)) = (first, last) else {
        return TestResult::Fail("no cursor writes");
    };
    if taken.len() != 2
        || released.len() != 2
        || taken.iter().any(|&t| t > first)
        || released.iter().any(|&r| r < last)
        || w.iter().any(|&(at, _)| at == lock(2) || at == lock(3))
    {
        return TestResult::Fail("each segment's OPP lock around the writes");
    }
    for (p, x, y, hot, dst) in want {
        let p = u64::from(p);
        let hubp = |r| e.io.regs.get(&l.hubp(p as u8, r)).copied().unwrap_or(0);
        if hubp(0x67d) != x << 15 | y
            || hubp(0x67e) != hot << 16
            || hubp(0x680) != dst
            || hubp(0x679) & 1 != 1
            || hubp(0x67c) != 64 << 16 | 64
            || e.io
                .regs
                .get(&e.cm(p as u8, CM_CONTROL))
                .copied()
                .unwrap_or(0)
                & 1
                != 1
        {
            return TestResult::Fail("per-pipe cursor registers");
        }
    }
    // Moved over the left segment's primary only: the overlay and the right
    // segment's pipes are written disabled.
    let moved = CursorApplied {
        x: 100,
        y: 100,
        ..a
    };
    let segments = placements(moved, odm_primary, &[Some(straddle), None, None], clocks);
    let moved = shown(moved, &segments);
    if moved.shown != 1 || e.program_cursor(moved, &segments).is_err() {
        return TestResult::Fail("move to one pipe");
    }
    for p in 1..4u8 {
        if e.io.regs.get(&l.hubp(p, 0x679)).copied().unwrap_or(0) & 1 != 0 {
            return TestResult::Fail("missed pipes disabled");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_programs_every_pipe_under_each_segment_lock
);

/// On harvested boards (pipe 0, pipe 1, pipes 1 and 2 fused) the cursor of
/// an ODM 2:1 stream on pipes 0 and the top pipe is programmed on both
/// pipes' HUBP/DPP instances inside the cursor locks of both pipes' OPP
/// instances (mpc1_cursor_lock(opp->inst)), and no write reaches or names
/// a fused instance.
fn dcn401_cursor_locks_each_segment_opp_instance_on_harvested_boards() -> TestResult {
    crate::amdgpu_dcn401_otg::tests::harvest::harvested(2, || {
        let top = crate::amdgpu_rdna4::pipe_pool().count() - 1;
        let mut e = engine();
        let l = e.layout;
        let primary = plane(
            0,
            (SplitPipes::one(top), SplitPipes::NONE),
            (3840, 2160),
            None,
        );
        e.status.surfaces[0] = Some(primary);
        let a = CursorApplied {
            pipe: 0,
            address: 0x8_00f0_0000,
            width: 64,
            height: 64,
            x: 1890,
            y: 600,
            visible: false,
            shown: 0,
            degamma: false,
        };
        let segments = placements(a, primary, &[None, None, None], (50_000, 594_000));
        let a = shown(a, &segments);
        if a.shown != 1 | 1 << top {
            return TestResult::Fail("cursor over both segments");
        }
        e.io.writes.clear();
        if e.program_cursor(a, &segments).is_err() || e.verify_cursor(a, &segments).is_err() {
            return TestResult::Fail("program");
        }
        for &(at, value) in &e.io.writes {
            crate::amdgpu_dcn401_otg::tests::harvest::guard(l, at, Some(value));
        }
        let lock = |inst: u8| l.mpc_base + (0x2c5 + u64::from(inst) * 5) * 4;
        let locked: alloc::vec::Vec<u8> = (0..4u8)
            .filter(|&i| {
                e.io.writes
                    .iter()
                    .any(|&(at, v)| at == lock(i) && v & 1 == 1)
            })
            .collect();
        let mut want = alloc::vec![l.inst(0), l.inst(top)];
        want.sort();
        if locked != want {
            return TestResult::Fail("locks of the segments' OPP instances");
        }
        for p in [0, top] {
            let at = e.layout.base + (0x679 + u64::from(l.inst(p)) * 0xdc) * 4;
            if e.io.regs.get(&at).copied().unwrap_or(0) & 1 != 1 {
                return TestResult::Fail("cursor enabled on the segment's HUBP instance");
            }
        }
        TestResult::Pass
    })
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_locks_each_segment_opp_instance_on_harvested_boards
);

/// amdgpu_dm_crtc_get_cursor_mode: DCN 4.0.1 (and 4.2.x, or a disabled
/// CRTC) always takes the native cursor, whatever lies under it; other DCN
/// take the overlay cursor over a YCbCr plane, a plane scaled unlike the
/// cursor in both directions, or a hole under the cursor.
fn dcn401_cursor_mode_follows_amdgpu_dm() -> TestResult {
    let one = plane_scale((64, 64), (64, 64), false);
    let scaled = CursorUnder {
        video: false,
        scale: plane_scale((1280, 720), (1920, 1080), false),
        covers_crtc: true,
    };
    let video = CursorUnder {
        video: true,
        scale: one,
        covers_crtc: true,
    };
    let full = CursorUnder {
        video: false,
        scale: one,
        covers_crtc: true,
    };
    let hole = CursorUnder {
        covers_crtc: false,
        ..full
    };
    if one != (1000, 1000) || scaled.scale != (1500, 1500) {
        return TestResult::Fail("dm_get_plane_scale");
    }
    if plane_scale((720, 1280), (1280, 720), true) != (1000, 1000) {
        return TestResult::Fail("rotated scale");
    }
    for planes in [&[scaled][..], &[video], &[hole], &[]] {
        if cursor_mode((4, 0, 1), true, one, planes) != CursorMode::Native {
            return TestResult::Fail("DCN 4.0.1 cursor not native");
        }
    }
    let dcn35 = (3, 5, 0);
    for (planes, want) in [
        (&[full][..], CursorMode::Native),
        (&[scaled], CursorMode::Overlay),
        (&[video], CursorMode::Overlay),
        (&[hole], CursorMode::Overlay),
        // A covering plane on top hides the scaled one below it.
        (&[full, scaled], CursorMode::Native),
        (&[hole, full], CursorMode::Native),
    ] {
        if cursor_mode(dcn35, true, one, planes) != want {
            return TestResult::Fail("DCN 3.5 cursor mode");
        }
    }
    if cursor_mode(dcn35, false, one, &[scaled]) != CursorMode::Native {
        return TestResult::Fail("disabled CRTC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_mode_follows_amdgpu_dm
);

/// amdgpu_dm_plane_handle_cursor_update asks for ENABLE_CURSOR_DEGAMMA
/// under the CRTC's legacy gamma (DCN401 has the dpp gamma_corr cap) and
/// dpp401_set_cursor_attributes turns it into CUR0_ROM_EN for the
/// premultiplied cursor; the cursor matrix stays bypassed
/// (dpp401_set_cursor_matrix) over every plane, YCbCr ones too. The ROM
/// follows the CRTC with each attribute update and is what the verifier
/// expects from the record.
fn dcn401_cursor_degamma_follows_legacy_gamma() -> TestResult {
    let mut e = engine();
    for legacy in [false, true] {
        e.displays.color[0] = Some(alloc::sync::Arc::new(ColorProgram {
            pre_degam_srgb: legacy,
            ..Default::default()
        }));
        if e.cursor_degamma(0) != legacy {
            return TestResult::Fail("ENABLE_CURSOR_DEGAMMA");
        }
        let a = CursorApplied {
            pipe: 0,
            address: 0x8_00f0_0000,
            width: 64,
            height: 64,
            x: 0,
            y: 0,
            visible: true,
            shown: 1,
            degamma: legacy,
        };
        let control = e.cm(0, CM_CONTROL);
        let matrix = e.cm(0, CM_MATRIX);
        let attributes = e.cursor_attributes(a, 0);
        let find = |at: u64| attributes.iter().find(|w| w.0 == at).copied();
        if find(control)
            != Some((
                control,
                CM_FIELDS & !ENABLE,
                2 << 4 | u32::from(legacy) << 3,
            ))
            || find(matrix) != Some((matrix, 3, 0))
        {
            return TestResult::Fail("cursor ROM and matrix words");
        }
    }
    e.displays.color[0] = None;
    if e.cursor_degamma(0) {
        return TestResult::Fail("no CRTC color asked for the ROM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-cursor",
    dcn401_cursor_degamma_follows_legacy_gamma
);
