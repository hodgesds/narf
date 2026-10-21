//! Live plane updates on the whole staged chain (`chain`): a running
//! scanout moves to new planes, takes and frees an overlay pipe, and is
//! checked afterwards exactly as a scanout started with those planes,
//! without its timing, OPP or link ever being touched.
use super::*;
use crate::amdgpu_dcn401_otg::{LivePlanes, PlaneContent, PlanesUpdated, UpdateType};
use crate::amdgpu_dcn401_spl::{Rect, Rotation};

/// ROUTES[1]: the display runs on pipe 2; pipe 3 is free for an overlay.
const OVERLAY_PIPE: u8 = 3;

fn primary(c: &Chain) -> SurfaceRequest {
    c.e.status.surfaces[usize::from(c.pipe)].unwrap().request
}
/// A 64x64 ARGB8888 overlay plane at (`x`, `y`) on the 640x480 stream.
fn overlay_at(q: u8, x: i32, y: i32) -> SurfaceRequest {
    SurfaceRequest {
        pipe: q,
        width: 64,
        height: 64,
        format: SurfaceFormat::Argb8888,
        odm: SplitPipes::NONE,
        mpc: SplitPipes::NONE,
        plane: Some(PlaneLayout {
            src: Rect::new(0, 0, 64, 64),
            dst: Rect::new(x, y, 64, 64),
            stream_width: 640,
            stream_height: 480,
            ycbcr420: false,
            rotation: Rotation::R0,
            blend: Blend::default_for(SurfaceFormat::Argb8888),
            underlay: false,
        }),
        surface: PlaneSurface::LINEAR,
    }
}
/// DML21's plan for the 640x480 stream with these planes (the unscaled
/// full-frame primary is implied). Boxed: plans are large and the aarch64
/// kernel-test stack is 64 KiB.
#[inline(never)]
fn plan_for(primary: SurfaceRequest, overlays: &[SurfaceRequest]) -> alloc::boxed::Box<dml::Plan> {
    let mut mode = plan().mode;
    mode.planes = [None; dml::MAX_PLANES];
    if primary.plane.is_some() {
        mode.planes[0] = Some(primary.dml_plane());
    }
    for (k, o) in overlays.iter().enumerate() {
        mode.planes[k + 1] = Some(o.dml_plane());
    }
    alloc::boxed::Box::new(dml::admit_all(&soc(), &[mode]).unwrap()[0])
}
/// prepare_bandwidth raised the shared clocks for `plan`: every timing
/// record carries them.
fn raise(c: &mut Chain, plan: &dml::Plan) {
    let mut r = c.clock;
    r.global.display_khz = r.global.display_khz.max(plan.clocks.dispclk_khz);
    r.global.dpp_khz = r.global.dpp_khz.max(plan.clocks.dpprefclk_khz);
    r.global.request.display_khz = r.global.display_khz;
    r.global.request.dpp_khz = r.global.dpp_khz;
    r.request.dpp_khz = r.request.dpp_khz.max(plan.clocks.dppclk_khz);
    let p = c.pipe;
    c.e.status.rebind_timing(p, |a| a.clock = r);
    c.clock = r;
}
/// Pipe `q` as a free pipe looks: powered, blank, drained and gated, out of
/// every tree, its DET left from a configuration before (compbuf smaller).
fn free_pipe(c: &mut Chain, q: u8) {
    let f = &mut c.e.io.inner.inner;
    f.forbidden_hubps &= !(1 << q);
    for (at, value) in [
        (BASE + (0x80 + u64::from(q) * 2) * 4, 0),
        (BASE + (0x81 + u64::from(q) * 2) * 4, 0),
        (h(q, HUBP_CONTROL), 3),
        (h(q, 0x5f5), 0),
        (h(q, 0x679), 0),
        (h(q, FLIP), 0),
        (h(q, 0x614), 0),
        (h(q, 0x5e7), 0x80),
        (h(q, 0x5f7), 0),
        (mpcc(q, MPC_STATUS), 1),
        (
            BASE + (0x4ba + u64::from(q) + 1) * 4,
            0x4000_0000 | (5 * 0x101),
        ),
    ] {
        f.regs.insert(at, value);
    }
    let crb0 = BASE + 0x4ba * 4;
    let v = f.regs.get(&crb0).copied().unwrap_or(0);
    f.regs.insert(crb0, (v & !0x1f1f) | (11 * 0x101));
    c.e.io.extra |= 1 << q;
}
/// One update, run to completion in its own frame (as Chain's steps).
#[inline(never)]
fn update(
    c: &mut Chain,
    live: &LivePlanes,
    plan: &dml::Plan,
) -> Result<alloc::boxed::Box<PlanesUpdated>, Error> {
    update_with(c, live, plan, &mut crate::amdgpu_dcn401_otg::Cleared)
}
/// `update` with fresh surfaces' first content from `content`.
#[inline(never)]
fn update_with(
    c: &mut Chain,
    live: &LivePlanes,
    plan: &dml::Plan,
    content: &mut dyn PlaneContent,
) -> Result<alloc::boxed::Box<PlanesUpdated>, Error> {
    let clock = c.clock;
    let p = c.pipe;
    c.e.io.inner.inner.writes.clear();
    run(c.surfaces.update_live_planes(
        &mut c.e,
        &c.pool,
        p,
        live,
        plan,
        CRYSTAL_KHZ,
        content,
        || Ok((clock, config())),
    ))
}
/// A first frame for pipe `q`'s fresh surface: row `y` of a 64-pixel-wide
/// plane is 0xff00_yy00 | x. Each chunk notes how many register writes the
/// update had made by then.
struct Pattern {
    q: u8,
    writes: Arc<AtomicUsize>,
    seen: Vec<usize>,
    /// Hand back a chunk past the surface's end instead.
    outside: bool,
}
impl PlaneContent for Pattern {
    fn chunk(&mut self, a: &SurfaceApplied, index: u32, words: &mut Vec<u32>) -> Option<u64> {
        if a.request.pipe != self.q || index >= a.request.height {
            return None;
        }
        self.seen.push(self.writes.load(Ordering::SeqCst));
        words.clear();
        words.extend((0..a.request.width).map(|x| 0xff00_0000 | index << 8 | x));
        Some(if self.outside {
            a.bytes
        } else {
            u64::from(index) * u64::from(a.pitch_bytes)
        })
    }
}
/// optimize_bandwidth after an update: the plan's exact watermarks.
#[inline(never)]
fn optimize(c: &mut Chain, plan: &dml::Plan) -> Result<(), Error> {
    use crate::amdgpu_dcn401_otg::WatermarkUpdate;
    let clock = c.clock;
    let p = c.pipe;
    run(c.surfaces.update_live_plan(
        &mut c.e,
        p,
        plan,
        WatermarkUpdate::Exact,
        CRYSTAL_KHZ,
        || Ok((clock, config())),
    ))
    .map(|_| ())
}
fn live(primary: SurfaceRequest, overlays: &[SurfaceRequest]) -> LivePlanes {
    let mut out = [None; MAX_OVERLAYS];
    for (o, s) in out.iter_mut().zip(overlays) {
        *o = Some(*s);
    }
    LivePlanes {
        primary,
        overlays: out,
        reset: false,
    }
}
/// No write of the last update touched the stream: its OTG enable and
/// clock, timing, ODM/OPTC source, DPG (blank) or DSC.
fn stream_untouched(c: &Chain) -> bool {
    // The model's (full-board) addresses, as the writes are recorded.
    let odm = |q: u8, r: u64| BASE + (r + u64::from(q) * 0x10) * 4;
    c.e.io.inner.inner.writes.iter().all(|&(at, _)| {
        (0..4u8).all(|q| {
            at != otg(q, 0x1b43)
                && at != otg(q, 0x1b84)
                && !(otg(q, 0x1b2a)..=otg(q, 0x1b3a)).contains(&at)
                && at != odm(q, SOURCE)
                && at != odm(q, MEMORY)
                && at != opp(q, DPG)
        })
    })
}
/// The index of the lock request and of its release among the last
/// update's writes; none unless exactly one of each.
fn lock_bracket(c: &Chain) -> Option<(usize, usize)> {
    let at = otg(c.pipe, LOCK);
    let w = &c.e.io.inner.inner.writes;
    let taken: Vec<usize> = (0..w.len())
        .filter(|&i| w[i].0 == at && w[i].1 & LOCK_REQUEST != 0)
        .collect();
    let released: Vec<usize> = (0..w.len())
        .filter(|&i| w[i].0 == at && w[i].1 & LOCK_REQUEST == 0)
        .collect();
    (taken.len() == 1 && released.len() == 1 && taken[0] < released[0])
        .then(|| (taken[0], released[0]))
}
/// Indices of the last update's writes to `at` (with `value` in `mask`).
fn written(c: &Chain, at: u64, mask: u32, value: u32) -> Vec<usize> {
    let w = &c.e.io.inner.inner.writes;
    (0..w.len())
        .filter(|&i| w[i].0 == at && w[i].1 & mask == value)
        .collect()
}
fn tree_regs(q: u8) -> [u64; 5] {
    [
        mpcc(q, 0),
        mpcc(q, 1),
        mpcc(q, 2),
        mpcc(q, 5),
        MPC_BASE + (0x2f2 + u64::from(q) * 4) * 4,
    ]
}

/// A medium/full update of the primary alone (placed and 3:4 downscaled
/// on its own pipe): one OTG lock around every write, the stream left
/// running, the same buffers (nothing allocated or released), the DSCL
/// programmed for SPL's new scaler, the tree re-inserted as dcn20_update_
/// mpcc does on a full update, and a check of the live scanout passes
/// afterwards.
fn dcn401_live_plane_update_scales_the_primary_in_place() -> TestResult {
    dcn401_live_plane_update_scales_the_primary_in_place_on(ROUTES[1])
}
/// The test above with the display on route (t, s, p).
pub(super) fn dcn401_live_plane_update_scales_the_primary_in_place_on(
    (t, s, p): (u8, u8, u8),
) -> TestResult {
    let mut c = chain(t, s, p);
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let mut scaled = primary(&c);
    scaled.plane = Some(PlaneLayout {
        src: Rect::new(0, 0, 640, 480),
        dst: Rect::new(80, 60, 480, 360),
        stream_width: 640,
        stream_height: 480,
        ycbcr420: false,
        rotation: Rotation::R0,
        blend: Blend::default_for(SurfaceFormat::Xrgb8888),
        underlay: false,
    });
    let plan = plan_for(scaled, &[]);
    raise(&mut c, &plan);
    let available = c.pool.available();
    let address = c.address;
    let Ok(u) = update(&mut c, &live(scaled, &[]), &plan) else {
        return TestResult::Fail("update");
    };
    if u.update != UpdateType::Full
        || (u.enabled, u.disabled, u.kept) != (0, 0, 1 << p)
        || u.released != 0
        || u.scanout.address != address
        || c.pool.available() != available
        || c.e.status.state != State::ScanoutRunning(p)
        || c.e.status.scanout.map(|r| r.plan) != Some(*plan)
        || c.e.status.surfaces[usize::from(p)].map(|a| a.request) != Some(scaled)
    {
        return TestResult::Fail("records after the update");
    }
    if !stream_untouched(&c) {
        return TestResult::Fail("the stream was touched");
    }
    let Some((lock, unlock)) = lock_bracket(&c) else {
        return TestResult::Fail("one OTG lock");
    };
    // Every plane register write lies inside the lock.
    let w = &c.e.io.inner.inner.writes;
    let plane_write = |at: u64| {
        (h(p, 0x5e5)..=h(p, 0x68d)).contains(&at)
            || (dpp_reg(p, 0xcc6)..=dpp_reg(p, 0xdc5)).contains(&at)
            || (mpcc(p, 0)..mpcc(p, 0x15)).contains(&at)
    };
    if w.iter()
        .enumerate()
        .any(|(i, &(at, _))| plane_write(at) && (i < lock || i > unlock))
    {
        return TestResult::Fail("plane write outside the lock");
    }
    // dcn20_update_mpcc: the MPCC out of its tree, then inserted at the
    // bottom again, the OUT_MUX following.
    let [top, bot, opp_id, lock_sel, mux] = tree_regs(p);
    let order: Vec<(u64, u32)> = w
        .iter()
        .filter(|&&(at, _)| [top, bot, opp_id, lock_sel, mux].contains(&at))
        .map(|&(at, v)| (at, v & 0xf))
        .collect();
    let q = u32::from(p);
    if order
        != [
            (mux, 0xf),
            (top, 0xf),
            (bot, 0xf),
            (opp_id, 0xf),
            (lock_sel, 0xf),
            (bot, 0xf),
            (top, q),
            (opp_id, q),
            (lock_sel, q),
            (mux, q),
        ]
    {
        return TestResult::Fail("tree re-insertion order");
    }
    // The DSCL holds SPL's new scaler.
    let (_, scaler) = scaled.scalers().next().unwrap();
    for op in crate::amdgpu_dcn401_dscl::program(&scaler, false) {
        if let crate::amdgpu_dcn401_dscl::Op::Write { reg, mask, value } = op {
            let skip = [
                crate::amdgpu_dcn401_dscl::SCL_COEF_RAM_TAP_SELECT,
                crate::amdgpu_dcn401_dscl::SCL_MODE,
            ];
            if !skip.contains(&reg)
                && !op_is_overwritten(&scaler, reg)
                && c.e.io.get(dpp_reg(p, reg)) & mask != value & mask
            {
                return TestResult::Fail("DSCL program");
            }
        }
    }
    // optimize_bandwidth, then the live scanout checks as started.
    if optimize(&mut c, &plan).is_err() || run(c.check()).is_err() {
        return TestResult::Fail("check after the update");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-plane-update",
    dcn401_live_plane_update_scales_the_primary_in_place
);
/// Whether a later write of the DSCL program changes `reg` again (only its
/// last value must hold).
fn op_is_overwritten(scaler: &crate::amdgpu_dcn401_spl::Scaler, reg: u64) -> bool {
    crate::amdgpu_dcn401_dscl::program(scaler, false)
        .iter()
        .filter(|op| matches!(op, crate::amdgpu_dcn401_dscl::Op::Write { reg: r, .. } if *r == reg))
        .count()
        > 1
}

/// An overlay added on a free pipe, moved, then removed, the timing
/// running throughout (amdgpu_dm's plane commits without a modeset):
/// - added: the new pipe is enabled off-tree before the lock (fetch clock,
///   aperture, requestor, DPP clock), its fresh cleared surface programmed
///   and unblanked under the OTG lock, the tree rebuilt top down (the
///   overlay's MPCC on the OPP's OUT_MUX above the primary's), the
///   watermarks only raised; a check of the live scanout with the overlay
///   passes;
/// - moved: a medium update, no tree write at all, the same buffers;
/// - removed: its MPCC leaves the tree and its cursor goes off under the
///   lock; only after the update latched is it drained, blanked and gated,
///   and its surface released to the pool.
fn dcn401_live_plane_update_adds_moves_and_removes_an_overlay() -> TestResult {
    dcn401_live_plane_update_adds_moves_and_removes_an_overlay_on(ROUTES[1], OVERLAY_PIPE)
}
/// The test above with the display on route (t, s, p) and the overlay on
/// pipe q.
pub(super) fn dcn401_live_plane_update_adds_moves_and_removes_an_overlay_on(
    (t, s, p): (u8, u8, u8),
    q: u8,
) -> TestResult {
    let mut c = chain(t, s, p);
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    free_pipe(&mut c, q);
    let base = primary(&c);
    let overlay = overlay_at(q, 100, 100);
    let plan = plan_for(base, &[overlay]);
    raise(&mut c, &plan);
    // Another display's higher urgent watermark stays (raise only).
    let wm_a = BASE + 0x4fe * 4;
    c.e.io.put(wm_a, 0x3fff);
    let available = c.pool.available();
    let Ok(u) = update(&mut c, &live(base, &[overlay]), &plan) else {
        return TestResult::Fail("add the overlay");
    };
    let Some(o) = u.scanout.overlays[0] else {
        return TestResult::Fail("overlay scanout record");
    };
    if u.update != UpdateType::Full
        || (u.enabled, u.disabled, u.kept) != (1 << q, 0, 1 << p)
        || o.pipe != q
        || o.address == 0
        || available - c.pool.available() != 64 * 256
        || c.e.io.get(wm_a) & 0x3fff != 0x3fff
        || !stream_untouched(&c)
    {
        return TestResult::Fail("overlay added");
    }
    let Some((lock, unlock)) = lock_bracket(&c) else {
        return TestResult::Fail("one OTG lock");
    };
    // dcn20_enable_plane before the lock; the unblank under it.
    let clock_on = written(&c, h(q, 0x5f5), 1, 1);
    let unblank = written(&c, h(q, HUBP_CONTROL), BLANK_EN, 0);
    if clock_on.first().is_none_or(|&i| i > lock)
        || unblank.len() != 1
        || !(lock..unlock).contains(&unblank[0])
    {
        return TestResult::Fail("enable before, unblank under the lock");
    }
    // The tree: the overlay inserted (alone) at the bottom first, then the
    // primary taken out and inserted below it; the OUT_MUX ends on the
    // overlay, which blends over the primary.
    let [_, _, _, _, mux] = tree_regs(p);
    let to_overlay = written(&c, mux, 0xf, u32::from(q));
    let overlay_top = written(&c, mpcc(q, 0), 0xf, u32::from(q));
    if to_overlay.len() != 1
        || overlay_top.first().is_none_or(|&i| i > to_overlay[0])
        || !(lock..unlock).contains(&to_overlay[0])
        || c.e.io.get(mpcc(q, 1)) & 0xf != u32::from(p)
        || c.e.io.get(mpcc(q, 3)) & 3 != 3
        || c.e.io.get(mpcc(p, 1)) & 0xf != 0xf
        || c.e.io.get(mpcc(p, 3)) & 3 != 2
    {
        return TestResult::Fail("overlay above the primary");
    }
    // optimize_bandwidth: the plan's exact watermarks, then the checks.
    if optimize(&mut c, &plan).is_err()
        || c.e.io.get(wm_a) & 0x3fff != plan.watermarks.urgent
        || run(c.check()).is_err()
    {
        return TestResult::Fail("check with the overlay");
    }
    // Moved: medium, nothing in the trees written, the same buffer.
    let moved = overlay_at(q, 300, 200);
    let plan2 = plan_for(base, &[moved]);
    raise(&mut c, &plan2);
    let Ok(u2) = update(&mut c, &live(base, &[moved]), &plan2) else {
        return TestResult::Fail("move the overlay");
    };
    let trees: Vec<u64> = tree_regs(p).into_iter().chain(tree_regs(q)).collect();
    if u2.update != UpdateType::Med
        || u2.scanout.overlays[0].map(|o| o.address) != Some(o.address)
        || u2.released != 0
        || c.e
            .io
            .inner
            .inner
            .writes
            .iter()
            .any(|(at, _)| trees.contains(at))
        || !stream_untouched(&c)
        || optimize(&mut c, &plan2).is_err()
        || run(c.check()).is_err()
    {
        return TestResult::Fail("overlay moved");
    }
    // Removed.
    let plan3 = plan_for(base, &[]);
    raise(&mut c, &plan3);
    let Ok(u3) = update(&mut c, &live(base, &[]), &plan3) else {
        return TestResult::Fail("remove the overlay");
    };
    let Some((lock, unlock)) = lock_bracket(&c) else {
        return TestResult::Fail("one OTG lock for the removal");
    };
    let disconnect = written(&c, mpcc(q, 0), 0xf, 0xf);
    let cursor_off = written(&c, h(q, 0x679), 1, 0);
    let blank = written(&c, h(q, HUBP_CONTROL), BLANK_EN, BLANK_EN);
    let gated = written(&c, h(q, 0x5f5), 1, 0);
    if u3.disabled != 1 << q
        || u3.released != 64 * 256
        || c.pool.available() != available
        || u3.scanout.overlays != [None; MAX_OVERLAYS]
        || disconnect
            .first()
            .is_none_or(|i| !(lock..unlock).contains(i))
        || cursor_off
            .first()
            .is_none_or(|i| !(lock..unlock).contains(i))
        || blank.first().is_none_or(|&i| i < unlock)
        || gated.first().is_none_or(|&i| i < unlock)
        || c.e.io.get(MPC_BASE + (0x2f2 + u64::from(p) * 4) * 4) & 0xf != u32::from(p)
        || c.e.io.get(h(q, HUBP_CONTROL)) & 0x1007 != 3
        || !stream_untouched(&c)
    {
        return TestResult::Fail("overlay removed");
    }
    // Its DET is released on this update (dcn401_program_front_end_for_ctx:
    // program_det_segments(0) under the lock, before the disconnect), and
    // the compressed buffer grows into it once the freed pipe is disabled
    // (optimize_bandwidth's program_compbuf_segments).
    let crb = |i: u64| BASE + (0x4ba + i) * 4;
    let det_freed = written(&c, crb(u64::from(q) + 1), 0x1f, 0);
    let compbuf = written(&c, crb(0), 0x1f, 16);
    if det_freed.len() != 1
        || !(lock..unlock).contains(&det_freed[0])
        || disconnect.first().is_none_or(|&i| i < det_freed[0])
        || compbuf.len() != 1
        || gated.first().is_none_or(|&i| i > compbuf[0])
        || c.e.io.get(crb(u64::from(q) + 1)) & 0x1f1f != 0
        || c.e.io.get(crb(u64::from(p) + 1)) & 0x1f1f != 5 * 0x101
        || c.e.io.get(crb(0)) & 0x1f1f != 16 * 0x101
        || c.e.status.requestor.map(|r| r.compbuf_bytes) != Some(16 * 65536)
    {
        return TestResult::Fail("freed DET and compbuf");
    }
    if optimize(&mut c, &plan3).is_err() || run(c.check()).is_err() {
        return TestResult::Fail("check after the removal");
    }
    // Added again: the DET comes back from the compressed buffer.
    raise(&mut c, &plan);
    if update(&mut c, &live(base, &[overlay]), &plan).is_err()
        || c.e.io.get(crb(u64::from(q) + 1)) & 0x1f1f != 5 * 0x101
        || c.e.io.get(crb(0)) & 0x1f1f != 11 * 0x101
        || optimize(&mut c, &plan).is_err()
        || run(c.check()).is_err()
    {
        return TestResult::Fail("overlay added again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-plane-update",
    dcn401_live_plane_update_adds_moves_and_removes_an_overlay
);

/// A plane added on a fresh surface shows its framebuffer from the update
/// itself, as DC scans the new plane's address from the update that adds
/// it: the first content is written into the cleared, unpublished surface
/// before the update's first register write, so the VUPDATE that latches
/// the unblanked overlay already fetches it. A chunk past the surface's
/// end refuses the update before any register write.
fn dcn401_live_plane_update_shows_the_first_frame_at_the_latch() -> TestResult {
    dcn401_live_plane_update_shows_the_first_frame_at_the_latch_on(ROUTES[1], OVERLAY_PIPE)
}
/// The test above with the display on route (t, s, p) and the overlay on
/// pipe q.
pub(super) fn dcn401_live_plane_update_shows_the_first_frame_at_the_latch_on(
    (t, s, p): (u8, u8, u8),
    q: u8,
) -> TestResult {
    let mut c = chain(t, s, p);
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    free_pipe(&mut c, q);
    let base = primary(&c);
    let overlay = overlay_at(q, 100, 100);
    let plan = plan_for(base, &[overlay]);
    raise(&mut c, &plan);
    let mut content = Pattern {
        q,
        writes: c.e.io.inner.writes.clone(),
        seen: Vec::new(),
        outside: true,
    };
    if update_with(&mut c, &live(base, &[overlay]), &plan, &mut content) != Err(Error::Invalid)
        || !c.e.io.inner.inner.writes.is_empty()
        || c.e.status.state != State::ScanoutRunning(p)
    {
        return TestResult::Fail("a chunk outside the surface");
    }
    let start = c.e.io.inner.writes.load(Ordering::SeqCst);
    content.outside = false;
    content.seen.clear();
    let Ok(u) = update_with(&mut c, &live(base, &[overlay]), &plan, &mut content) else {
        return TestResult::Fail("add the overlay");
    };
    let Some(o) = u.scanout.overlays[0] else {
        return TestResult::Fail("overlay scanout record");
    };
    if content.seen.len() != 64 || content.seen.iter().any(|&n| n != start) {
        return TestResult::Fail("first content after a register write");
    }
    let Some(a) = c.e.status.surfaces[usize::from(q)] else {
        return TestResult::Fail("overlay surface record");
    };
    for (x, y) in [(0u32, 0u32), (63, 0), (17, 31), (0, 63), (63, 63)] {
        let at = u64::from(y) * u64::from(a.pitch_bytes) + u64::from(x) * 4;
        if c.vram(o.address, at) != 0xff00_0000 | y << 8 | x {
            return TestResult::Fail("first content in the surface");
        }
    }
    if !stream_untouched(&c) || optimize(&mut c, &plan).is_err() || run(c.check()).is_err() {
        return TestResult::Fail("check with the overlay");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-plane-update",
    dcn401_live_plane_update_shows_the_first_frame_at_the_latch
);

/// Refusals leave the scanout exactly as it ran, without a register
/// write: a plane on the display's own pipe, a pipe another plane holds
/// or one not free, a plan for other planes, a display not scanning out.
fn dcn401_live_plane_update_refuses_before_any_write() -> TestResult {
    dcn401_live_plane_update_refuses_before_any_write_on(ROUTES[1], OVERLAY_PIPE)
}
/// The test above with the display on route (t, s, p) and the overlay on
/// pipe q.
pub(super) fn dcn401_live_plane_update_refuses_before_any_write_on(
    (t, s, p): (u8, u8, u8),
    q: u8,
) -> TestResult {
    let mut c = chain(t, s, p);
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let base = primary(&c);
    let overlay = overlay_at(q, 100, 100);
    let plan = plan_for(base, &[overlay]);
    raise(&mut c, &plan);
    let refused = |c: &mut Chain, l: LivePlanes, plan: &dml::Plan, want: Error| {
        update(c, &l, plan) == Err(want)
            && c.e.io.inner.inner.writes.is_empty()
            && c.e.status.state == State::ScanoutRunning(p)
    };
    // The overlay on the primary's pipe.
    if !refused(
        &mut c,
        live(base, &[overlay_at(p, 100, 100)]),
        &plan,
        Error::Invalid,
    ) {
        return TestResult::Fail("overlay on the primary's pipe");
    }
    // Pipe 3 is not free yet (its HUBP gated off in the fixture is fine,
    // but its MPCC is in an inherited, busy state).
    c.e.io.inner.inner.forbidden_hubps &= !(1 << q);
    c.e.io.put(mpcc(q, MPC_STATUS), 2);
    c.e.io.put(BASE + (0x80 + u64::from(q) * 2) * 4, 0);
    c.e.io.put(BASE + (0x81 + u64::from(q) * 2) * 4, 0);
    if !refused(&mut c, live(base, &[overlay]), &plan, Error::Busy) {
        return TestResult::Fail("busy pipe");
    }
    free_pipe(&mut c, q);
    // A plan admitted for other planes is not this one's.
    let other = plan_for(base, &[overlay_at(q, 0, 0), overlay_at(1, 200, 200)]);
    if !refused(&mut c, live(base, &[overlay]), &other, Error::Invalid) {
        return TestResult::Fail("unbound plan");
    }
    if run(c.stop()).is_err() || update(&mut c, &live(base, &[overlay]), &plan) != Err(Error::Busy)
    {
        return TestResult::Fail("not scanning out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-plane-update",
    dcn401_live_plane_update_refuses_before_any_write
);

/// The cursor follows the planes: over the new overlay it is programmed
/// on the overlay's pipe too (both enabled, as dcn401_set_cursor_position
/// leaves them: the overlay does not contain the primary's recout), in
/// that pipe's recout space; with the overlay gone, on the primary's
/// alone again.
fn dcn401_live_plane_update_moves_the_cursor_with_the_planes() -> TestResult {
    dcn401_live_plane_update_moves_the_cursor_with_the_planes_on(ROUTES[1], OVERLAY_PIPE)
}
/// The test above with the display on route (t, s, p) and the overlay on
/// pipe q.
pub(super) fn dcn401_live_plane_update_moves_the_cursor_with_the_planes_on(
    (t, s, p): (u8, u8, u8),
    q: u8,
) -> TestResult {
    let mut c = chain(t, s, p);
    if run(c.start()).is_err() {
        return TestResult::Fail("start");
    }
    let image = alloc::vec![0x8000_0000u32; 32 * 32];
    let set = c
        .surfaces
        .set_cursor(&mut c.e, &c.pool, config(), p, (32, 32, &image), (110, 120));
    if set.map(|a| a.shown) != Ok(1 << p) {
        return TestResult::Fail("cursor on the primary");
    }
    free_pipe(&mut c, q);
    let base = primary(&c);
    let overlay = overlay_at(q, 100, 100);
    let plan = plan_for(base, &[overlay]);
    raise(&mut c, &plan);
    if update(&mut c, &live(base, &[overlay]), &plan).is_err() {
        return TestResult::Fail("add the overlay");
    }
    let Some(cursor) = c.e.status.cursor else {
        return TestResult::Fail("cursor record");
    };
    // Recout space: the overlay's recout starts at (100, 100).
    if cursor.shown != (1 << p | 1 << q)
        || c.e.io.get(h(q, 0x679)) & 1 != 1
        || c.e.io.get(h(q, 0x67d)) != 10 << 15 | 20
        || c.e.io.get(h(p, 0x67d)) != 110 << 15 | 120
        || optimize(&mut c, &plan).is_err()
        || run(c.check()).is_err()
    {
        return TestResult::Fail("cursor on both planes");
    }
    let plan2 = plan_for(base, &[]);
    raise(&mut c, &plan2);
    if update(&mut c, &live(base, &[]), &plan2).is_err()
        || c.e.status.cursor.map(|a| a.shown) != Some(1 << p)
        || c.e.io.get(h(q, 0x679)) & 1 != 0
        || optimize(&mut c, &plan2).is_err()
        || run(c.check()).is_err()
    {
        return TestResult::Fail("cursor back on the primary");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-plane-update",
    dcn401_live_plane_update_moves_the_cursor_with_the_planes
);
