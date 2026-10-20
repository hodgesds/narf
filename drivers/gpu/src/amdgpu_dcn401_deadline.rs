//! Native DCN401 per-pipe DLG/TTU deadlines (both pipes of an ODM pair)
//! and DCHUBBUB watermarks from an admitted `amdgpu_dcn401_dml::Plan`.
//! Linux: hubp401_setup, hubp401_setup_interdependent, hubp401_program_deadline,
//! hubp401_vready_at_or_After_vsync, hubbub401_program_watermarks,
//! hubbub1_allow_self_refresh_control and dcn401_program_arbiter.
//! Fetch stays stopped and routes detached; this is not activation.
use super::*;
use crate::amdgpu_dcn401_dml as dml;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

const DEBUG_DB: u64 = 0x5fc; // HUBPREQ_DEBUG_DB
const MISSION_MODE: u32 = 1 << 8;
const QOS_WM: u64 = 0x621;
const GLOBAL_TTU: u64 = 0x622;
const SURF0_TTU0: u64 = 0x623;
const SURF0_TTU1: u64 = 0x624;
const SURF1_TTU0: u64 = 0x625;
const SURF1_TTU1: u64 = 0x626;
const CUR0_TTU0: u64 = 0x627;
const CUR0_TTU1: u64 = 0x628;
const DMDATA_VM: u64 = 0x62b;
const BLANK0: u64 = 0x63b;
const BLANK1: u64 = 0x63c;
const DST_DIMENSIONS: u64 = 0x63d;
const DST_AFTER: u64 = 0x63e;
const PREFETCH: u64 = 0x63f;
const PREFETCH_C: u64 = 0x640;
const VBLANK0: u64 = 0x641;
const FLIP0: u64 = 0x646;
const PER_LINE_PRE: u64 = 0x651;
const PER_LINE: u64 = 0x652;
const REF_FREQ: u64 = 0x654;
const LUT3D_DLG: u64 = 0x68d;
const VREADY_AFTER_VSYNC: u32 = 1 << 8; // DCHUBP_CNTL
                                        // DCHUBBUB, DCN bank 2.
const SDPIF_RATE_LIMIT: u64 = 0x485;
const DRAM_STATE: u64 = 0x4fc;
const USR_RETRAINING: u64 = 0x4fd;
const WM_A: u64 = 0x4fe;
const WM_B: u64 = 0x511;
const CTRL_STATUS: u64 = 0x53a;
const TIMEOUT_CTRL2: u64 = 0x541;
/// SELF_REFRESH_FORCE_ENABLE without FORCE_VALUE: never allow stutter.
const SELF_REFRESH_DISALLOWED: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlinesApplied {
    pub pipe: u8,
    /// The admitted plan these registers were programmed from.
    pub plan: dml::Plan,
    /// `HUBP_VREADY_AT_OR_AFTER_VSYNC` from Linux's hwseq rule.
    pub vready_after_vsync: bool,
}

/// `hubp401_vready_at_or_After_vsync`, with Linux's unsigned underflow
/// (VREADY before the start of blank) treated as "before".
fn vready_after_vsync(plan: &dml::Plan) -> bool {
    let (t, s) = (plan.mode.timing, plan.sync);
    let vblank_end = t.v_total - t.v_front_porch - t.v_active;
    let width = s.vready_offset + s.vupdate_width + s.vupdate_offset;
    s.vstartup
        .checked_sub(width / t.h_total)
        .is_some_and(|lines| lines <= vblank_end)
}
/// Per-pipe DLG/TTU fields, `hubp401_program_deadline` then
/// `hubp401_setup_interdependent` order: a 4:2:0 plane's chroma line and
/// request delivery beside luma's (zero for RGB). VM/PTE/meta/flip/cursor and
/// 3D-LUT fields are explicitly zero: none is enabled in the admitted shape.
fn hubp(t: dml::Ttu, d: dml::Dlg) -> [(u64, u32, u32); 31] {
    let zero23 = 0x7fffff;
    [
        (
            BLANK0,
            0x7fff1fff,
            d.refcyc_h_blank_end | d.dlg_vblank_end << 16,
        ),
        (BLANK1, 0x3ffff, d.min_dst_y_next_start),
        (DST_DIMENSIONS, 0x1fffff, d.refcyc_per_htotal),
        (
            DST_AFTER,
            0x71fff,
            d.refcyc_x_after_scaler | d.dst_y_after_scaler << 16,
        ),
        (REF_FREQ, 0x1fffff, d.ref_freq_to_pix_freq),
        (0x642, zero23, 0),  // REFCYC_PER_PTE_GROUP_VBLANK_L
        (0x649, 0x1ffff, 0), // DST_Y_PER_PTE_ROW_NOM_L
        (0x64a, zero23, 0),  // REFCYC_PER_PTE_GROUP_NOM_L
        (0x64d, 0x1ffff, 0), // DST_Y_PER_META_ROW_NOM_L
        (0x64e, zero23, 0),  // REFCYC_PER_META_CHUNK_NOM_L
        (
            PER_LINE,
            0x1fff1fff,
            d.refcyc_per_line_delivery_l | d.refcyc_per_line_delivery_c << 16,
        ),
        (0x643, zero23, 0),  // REFCYC_PER_PTE_GROUP_VBLANK_C
        (0x64b, 0x1ffff, 0), // DST_Y_PER_PTE_ROW_NOM_C
        (0x64c, zero23, 0),  // REFCYC_PER_PTE_GROUP_NOM_C
        (0x64f, 0x1ffff, 0), // DST_Y_PER_META_ROW_NOM_C
        (0x650, zero23, 0),  // REFCYC_PER_META_CHUNK_NOM_C
        (
            QOS_WM,
            0x3fff3fff,
            t.qos_level_low_wm | t.qos_level_high_wm << 16,
        ),
        (
            SURF0_TTU0,
            0x1f7fffff,
            t.refcyc_per_req_delivery_l | t.qos_level_fixed_l << 24,
        ),
        (
            SURF1_TTU0,
            0x1f7fffff,
            t.refcyc_per_req_delivery_c | t.qos_level_fixed_c << 24,
        ),
        (CUR0_TTU0, 0x1f7fffff, 0),
        (0x647, zero23, 0), // REFCYC_PER_PTE_GROUP_FLIP_L
        (LUT3D_DLG, zero23, 0),
        (DMDATA_VM, 0xffff, 0), // REFCYC_PER_VM_DMDATA only; status untouched
        (
            PREFETCH,
            0xff3fffff,
            d.vratio_prefetch | d.dst_y_prefetch << 24,
        ),
        (PREFETCH_C, 0x3fffff, d.vratio_prefetch_c),
        (
            VBLANK0,
            0x3f7f,
            d.dst_y_per_vm_vblank | d.dst_y_per_row_vblank << 8,
        ),
        (FLIP0, 0x3f7f, 0),
        (0x644, zero23, 0), // REFCYC_PER_META_CHUNK_VBLANK_L
        (0x645, zero23, 0), // REFCYC_PER_META_CHUNK_VBLANK_C
        (0x648, zero23, 0), // REFCYC_PER_META_CHUNK_FLIP_L
        (
            PER_LINE_PRE,
            0x1fff1fff,
            d.refcyc_per_line_delivery_pre_l | d.refcyc_per_line_delivery_pre_c << 16,
        ),
    ]
}
/// The remaining interdependent TTU fields; the global TTU write preserves
/// the flush/row-TTU mode bits Linux leaves alone.
fn hubp_ttu(t: dml::Ttu) -> [(u64, u32, u32); 4] {
    [
        (SURF0_TTU1, 0x7fffff, t.refcyc_per_req_delivery_pre_l),
        (SURF1_TTU1, 0x7fffff, t.refcyc_per_req_delivery_pre_c),
        (CUR0_TTU1, 0x7fffff, 0),
        (
            GLOBAL_TTU,
            0xf0ffffff,
            t.min_ttu_vblank | t.qos_level_flip << 28,
        ),
    ]
}
/// One DCHUBBUB watermark set, `hubbub401_program_*_watermarks` layout:
/// every SR level gets the same enter/exit pair, and the temperature-read
/// watermark occupies both UCLK and FCLK "1" slots.
fn watermark_set(base: u64, w: &dml::Watermarks) -> [(u64, u32, u32); 19] {
    [
        (base, 0x3fff, w.urgent),
        (base + 1, 0x3fff, w.usr),
        (base + 2, 0x3fff, w.refcyc_per_trip_to_mem),
        (base + 3, 0x3fff, w.refcyc_per_meta_trip_to_mem),
        (base + 4, 0xffff, w.sr_enter),
        (base + 5, 0xffff, w.sr_exit),
        (base + 6, 0xffff, w.sr_enter),
        (base + 7, 0xffff, w.sr_exit),
        (base + 8, 0xffff, w.sr_enter),
        (base + 9, 0xffff, w.sr_exit),
        (base + 10, 0xffff, w.sr_enter),
        (base + 11, 0xffff, w.sr_exit),
        (base + 12, 0xffff, w.uclk_pstate),
        (base + 13, 0xffff, w.temp_read),
        (base + 14, 0xffff, w.fclk_pstate),
        (base + 15, 0xffff, w.temp_read),
        (base + 16, 0x3ff, w.frac_urg_bw_nom),
        (base + 17, 0x3ff, w.frac_urg_bw_flip),
        (base + 18, 0x3ff, w.frac_urg_bw_mall),
    ]
}
/// Global arbiter state. Linux DCN401 leaves SAT_LEVEL/MIN_REQ_OUTSTAND
/// alone, sets the request limit at init, the stall threshold and
/// HW_DEBUG[5] (`allow_sdpif_rate_limit_when_cstate_req`, clear) per mode,
/// and USR retraining unforced. Self-refresh is forced off: the native policy
/// has not validated stutter, although the plan budgets its blank. The DCHUB
/// pstate force is left released; PMFW keeps UCLK switching disabled, and
/// GDDR6 temperature reads use the same allow path.
fn arbiter(plan: &dml::Plan) -> [(u64, u32, u32); 5] {
    [
        (
            SDPIF_RATE_LIMIT,
            0xfff,
            plan.arbiter.sdpif_request_rate_limit,
        ),
        (DRAM_STATE, 3, SELF_REFRESH_DISALLOWED),
        (USR_RETRAINING, 0x300, 0),
        (
            TIMEOUT_CTRL2,
            0x7ffffff,
            plan.arbiter.pstate_stall_threshold,
        ),
        (CTRL_STATUS, 1 << 9, 0),
    ]
}

impl<I: Io> Engine<I> {
    pub(super) fn deadline_writes(
        &mut self,
        pipe: u8,
        plan: &dml::Plan,
        verify: bool,
    ) -> Result<(), Error> {
        let l = self.layout;
        let hubbub = |reg| l.base + reg * 4;
        let each = |e: &mut Self, at: u64, mask: u32, value: u32| {
            if verify {
                if e.read(at)? & mask != value & mask {
                    return Err(Error::Readback(at));
                }
                Ok(())
            } else {
                e.update(at, mask, value)
            }
        };
        // Every HUBP each plane fetches on, the primary first and then the
        // staged overlays bottom up (the plan's planes in order): an ODM
        // pipe gets its plane's DLG/TTU values but for its own blank end
        // (Plan::plane_dlg).
        let mut planes: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            alloc::vec![self.fetch_pipes(pipe).collect()];
        if let Some(r) = self.status.requestor.filter(|r| r.pipe == pipe) {
            for o in r.overlays.iter().flatten() {
                planes.push(o.request.segments().map(|(p, _, _)| p).collect());
            }
        }
        let segments = planes
            .iter()
            .enumerate()
            .flat_map(|(k, pipes)| pipes.iter().enumerate().map(move |(i, &p)| (k, i as u8, p)));
        let segments: alloc::vec::Vec<(usize, u8, u8)> = segments.collect();
        for (k, i, p) in segments {
            let dlg = plan.plane_dlg(k, i).ok_or(Error::Invalid)?;
            let ttu = plan.plane(k).ok_or(Error::Invalid)?.ttu;
            // Linux writes the whole register to enter DLG mission mode and
            // never reads it back; only that bit is required to read back.
            let debug = l.hubp(p, DEBUG_DB);
            if verify {
                if self.read(debug)? & MISSION_MODE == 0 {
                    return Err(Error::Readback(debug));
                }
            } else {
                self.access(|io| {
                    io.write(debug, MISSION_MODE);
                    Ok(())
                })?;
            }
            for (r, mask, value) in hubp(ttu, dlg).into_iter().chain(hubp_ttu(ttu)) {
                each(self, l.hubp(p, r), mask, value)?;
            }
            let vready = if vready_after_vsync(plan) {
                VREADY_AFTER_VSYNC
            } else {
                0
            };
            each(self, l.hubp(p, HUBP_CONTROL), VREADY_AFTER_VSYNC, vready)?;
        }
        for set in [WM_A, WM_B] {
            for (r, mask, value) in watermark_set(set, &plan.watermarks) {
                each(self, hubbub(r), mask, value)?;
            }
        }
        for (r, mask, value) in arbiter(plan) {
            each(self, hubbub(r), mask, value)?;
        }
        Ok(())
    }
}
/// Whether `surface`'s layout is a plane of the stream `plan` admitted:
/// on a stream of its size and encoding, split like it, and exactly the
/// surface, viewport, ratios and taps DML planned (`dml_plane`).
fn plane_bound(
    plan: &dml::Plan,
    timing: Request,
    surface: SurfaceApplied,
    planned: dml::Plane,
) -> bool {
    let t = plan.mode.timing;
    let l = surface.request.layout();
    l.stream_width == t.h_active
        && l.stream_height == t.v_active
        && l.ycbcr420 == plan.mode.ycbcr420
        && surface.request.odm.is_some() == timing.odm.is_some()
        && surface.request.dml_plane() == planned
        && u64::from(surface.pitch_bytes)
            == u64::from(planned.pitch) * u64::from(planned.bytes_per_pixel)
}
/// Every owner the plan was admitted against must still be the one in place:
/// a plan is only valid for exactly this timing, sync, DP SST or TMDS signal,
/// these planes (the primary's surface and placement, then each overlay's),
/// DET and DCHUB reference, and for at least its clocks with the pinned
/// UCLK/DCFCLK floors it assumed. The plan is also re-admitted, so a value
/// built or edited outside admission is refused.
pub(super) fn bound(
    plan: &dml::Plan,
    timing: Request,
    a: RequestorApplied,
    clock: dccg::Applied,
    dchub_refclk_khz: u32,
) -> bool {
    let t = plan.mode.timing;
    let surfaces = core::iter::once(a.surface).chain(a.overlays.iter().flatten().copied());
    let planes: alloc::vec::Vec<dml::Plane> = plan.mode.plane_list().collect();
    plan.readmits()
        && timing.pipe == a.pipe
        && timing.timing == t
        && timing.sync == plan.sync
        && matches!(
            timing.signal,
            Signal::DisplayPort | Signal::HpoDisplayPort | Signal::Tmds
        )
        && a.surface.request.odm == timing.odm
        && plan.pipes == 1 + u8::from(timing.odm.is_some())
        && surfaces.clone().count() == planes.len()
        && surfaces
            .zip(planes)
            .all(|(s, p)| plane_bound(plan, timing, s, p))
        && plan
            .planes
            .iter()
            .flatten()
            .all(|p| p.det_bytes == a.det_bytes)
        && a.det_bytes == plan.det_bytes
        && clock.request.pipe == a.pipe
        && clock.global.display_khz >= plan.clocks.dispclk_khz
        && clock.global.dpp_khz >= plan.clocks.dpprefclk_khz
        && clock.request.dpp_khz >= plan.clocks.dppclk_khz
        && clock.global.memory_floor_khz == plan.soc.uclk_khz
        && clock.global.dcf_floor_khz == plan.soc.dcfclk_khz[1]
        && dchub_refclk_khz == plan.soc.dchub_refclk_khz
}
impl Surfaces {
    fn bind_deadlines<I: Io>(
        &self,
        e: &mut Engine<I>,
        a: RequestorApplied,
        plan: &dml::Plan,
        (clock, config): (dccg::Applied, DisplayContext),
        crystal_khz: u32,
    ) -> Result<(), Error> {
        let mpc = e.status.mpcs[usize::from(a.pipe)].ok_or(Error::Invalid)?;
        self.verify_mpc_source(e, mpc, (clock, config))?;
        e.verify_mpc(mpc)?;
        for o in a.overlays.iter().flatten() {
            let m = e.status.mpcs[usize::from(o.request.pipe)].ok_or(Error::Invalid)?;
            if m.dpp.surface != *o {
                return Err(Error::Invalid);
            }
            self.verify_mpc_source(e, m, (clock, config))?;
            e.verify_mpc(m)?;
        }
        e.verify_requestor(a.pipe)?;
        let refclk = e.dchub_refclk_khz(crystal_khz)?;
        if !bound(plan, mpc.dpp.timing.request, a, clock, refclk) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_deadlines<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        plan: &dml::Plan,
        crystal_khz: u32,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<DeadlinesApplied, Error> {
        if !e.status.state.reusable() || e.status.deadlines.is_some() {
            return Err(Error::Busy);
        }
        let a = e.status.requestor.ok_or(Error::Invalid)?;
        if a.pipe != pipe {
            return Err(Error::Invalid);
        }
        let current = owners()?;
        self.bind_deadlines(e, a, plan, current, crystal_khz)?;
        e.requestor_errors(pipe)?;
        e.status.state = State::PreparingDeadlines(pipe);
        let result = async {
            // Fetch is stopped and blank; the HUBP clocks are enabled only
            // around programming, as for the requestor.
            let pipes = e.plane_pipes(pipe);
            for &p in &pipes {
                e.update(e.layout.hubp(p, HUBP_CLOCK), 1, 1)?;
                e.wait(e.layout.hubp(p, HUBP_CONTROL), 0x1007, 3, 100_000)
                    .await?;
            }
            e.requestor_errors(pipe)?;
            e.deadline_writes(pipe, plan, false)?;
            for &p in &pipes {
                e.update(e.layout.hubp(p, HUBP_CLOCK), 1, 0)?;
            }
            if owners()? != current {
                return Err(Error::Busy);
            }
            self.bind_deadlines(e, a, plan, current, crystal_khz)?;
            e.deadline_writes(pipe, plan, true)?;
            e.requestor_errors(pipe)
        }
        .await;
        match result {
            Ok(()) => {
                let report = DeadlinesApplied {
                    pipe,
                    plan: *plan,
                    vready_after_vsync: vready_after_vsync(plan),
                };
                e.status.deadlines = Some(report);
                e.status.state = State::DeadlinesPrepared;
                Ok(report)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}
impl Otg {
    /// Program the admitted plan's DLG/TTU deadlines and DCHUBBUB watermarks
    /// for a pipe whose requestor is staged, after re-admitting the plan and
    /// binding it to every current owner. Self-refresh is forced off.
    /// Fetch stays stopped; this neither connects routes nor starts scanout.
    /// # Safety
    /// Retain every owner and inherited resource on success, error and
    /// cancellation. Exclude firmware/FAMS and concurrent display/hub/VM/IRQ/
    /// clock/reset/power writers; no other pipe may be fetching.
    pub async unsafe fn prepare_deadlines(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        plan: &dml::Plan,
        crystal_khz: u32,
    ) -> Result<DeadlinesApplied, Error> {
        let regs = self.0.io.0;
        let (held, layout) = self.0.held();
        // Each overlay's DPP runs on its own DPP-only clock (as an ODM
        // pipe's), at least at its plane's DPPCLK, from the global clocks.
        if let Some(r) = self.0.status.requestor.filter(|r| r.pipe == pipe) {
            for (k, o) in r.overlays.iter().enumerate() {
                let Some(o) = o else { continue };
                let want = plan.plane(k + 1).ok_or(Error::Invalid)?.dppclk_khz;
                for (q, _, _) in o.request.segments() {
                    let c = dccg
                        .segment_clock(regs, clocks, q, &|at| held_by_sibling(held, layout, at))
                        .map_err(Error::PipeClocks)?;
                    if c.request.dpp_khz < want || c.global.dpp_khz < plan.clocks.dpprefclk_khz {
                        return Err(Error::Invalid);
                    }
                }
            }
        }
        self.1
            .prepare_deadlines(&mut self.0, pipe, plan, crystal_khz, || {
                Ok((
                    dccg.timing_clock_except(regs, clocks, pipe, &|at| {
                        held_by_sibling(held, layout, at)
                    })
                    .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_deadline_tests.rs"]
mod tests;
