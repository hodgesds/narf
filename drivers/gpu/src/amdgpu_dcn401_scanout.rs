//! Native DCN401 single-pipe scanout start and stop on a running legacy DP
//! SST black-video stream. Linux: commit_planes_for_stream with
//! dcn401_interdependent_update_lock/optc3_lock, dcn401_program_pipe
//! (dcn20_blank_pixel_data, dcn20_update_dchubp_dpp/mpc1_insert_plane,
//! hubp401_program_surface_flip_and_addr, hubp2_set_blank) and
//! dcn401_post_unlock_program_front_end's flip/EARLIEST_INUSE check; the stop
//! path follows mpc1_remove_mpcc, dcn10_wait_for_mpcc_disconnect and
//! dcn20_plane_atomic_disable without power-gating the staged plane.
use super::*;
use crate::amdgpu_dcn401_dml as dml;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};
use narf_graphics_driver::generic::GenericFb;

const DPP_CONTROL: u64 = 0xcc5; // DPP_TOP, stride 0x16b
const DPP_CLOCK_ENABLE: u32 = 0x10;
const ADDRESS: u64 = 0x60a;
const ADDRESS_HIGH: u64 = 0x60b;
/// DCSURF_PRIMARY_SURFACE_ADDRESS_C and _HIGH_C: a 4:2:0 plane's chroma.
const ADDRESS_C: u64 = 0x60c;
const ADDRESS_HIGH_C: u64 = 0x60d;
/// DCSURF_SURFACE_PITCH and DCSURF_SURFACE_PITCH_C (PITCH, PITCH_C).
const PITCH: u64 = 0x607;
const PITCH_C: u64 = 0x608;
const EARLIEST_INUSE: u64 = 0x61c;
const EARLIEST_INUSE_HIGH: u64 = 0x61d;
const FLIP_PENDING: u32 = 0x100;
const CURSOR_REQ_MODE: u32 = 4;
const BLANK_EN: u32 = 1;
const NO_OUTSTANDING: u32 = 2;
const TTU_DISABLE: u32 = 0x1000;
const HUBP_UNDERFLOW: u32 = 0x7000_0000;
const HUBP_UNDERFLOW_CLEAR: u32 = 0x8000_0000;
const DPG: u64 = 0x1854;
const DPG_FIELDS: u32 = 0x01ff_3171;
const DPG_EN: u32 = 1;
const DPG_PENDING: u64 = 0x185b;
const OPTC_INPUT: u64 = 0x1aca; // ODM stride 0x10
const OPTC_PENDING: u32 = 0x8000_0000;
const OPTC_UNDERFLOW: u32 = 0x400;
const OPTC_UNDERFLOW_CLEAR: u32 = 0x1000;
const OTG_MASTER_EN: u32 = 1;
const DOUBLE_BUFFER: u64 = 0x1b5c;
const OTG_UPDATE_PENDING: u32 = 1;
const PIPE_UPDATE: u64 = 0x1b9e;
const PIPE_PENDING: u32 = 0x11; // flip and DC register update pending
const GLOBAL_CONTROL2: u64 = 0x1b90;
const LOCK_SELECT: u32 = 0x0e00_0000;
const LOCK_REQUEST: u32 = 1;
const LOCK_STATUS: u32 = 0x100;
const FRAME_COUNT: u64 = 0x1b4d;
const FRAME_MASK: u32 = 0xff_ffff;
const STATUS_POSITION: u64 = 0x1b4a;
const V_BLANK_START_END: u64 = 0x1b38;
const MPC_STATUS: u64 = 0xe;
const MPCC_CONTROL: u64 = 3;
const MPCC_MODE_TOP_ONLY: u32 = 2;
const MPCC_MODE_TOP_BOT: u32 = 3;
const DRAM_STATE: u64 = 0x4fc;
const PSTATE_FORCE: u32 = 0x30; // ALLOW_PSTATE_CHANGE_FORCE_{VALUE,ENABLE}
const PSTATE_DISALLOWED: u32 = 0x20;

/// One overlay plane of a scanout: its pipe (and ODM pipes, or MPC
/// slices' pipes), fetching `address` above the planes below it, or below
/// the primary for an underlay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayScanout {
    pub pipe: u8,
    pub odm: SplitPipes,
    pub mpc: SplitPipes,
    pub address: u64,
    pub underlay: bool,
}
impl OverlayScanout {
    pub(super) fn of(s: SurfaceApplied) -> Self {
        Self {
            pipe: s.request.pipe,
            odm: s.request.odm,
            mpc: s.request.mpc,
            address: s.address,
            underlay: s.request.layout().underlay,
        }
    }
    /// Its pipes with the ODM segment each feeds.
    fn pipes(&self) -> impl Iterator<Item = (u8, usize)> + Clone {
        plane_pipes(self.pipe, self.odm, self.mpc)
    }
}

/// A plane's pipes, the first first, each with the ODM segment (OPP) its
/// MPCC blends into: one per segment with ODM, every MPC slice on the one
/// segment without.
fn plane_pipes(
    pipe: u8,
    odm: SplitPipes,
    mpc: SplitPipes,
) -> impl Iterator<Item = (u8, usize)> + Clone {
    let odm = odm.into_iter().enumerate().map(|(k, p)| (p, k + 1));
    core::iter::once((pipe, 0))
        .chain(odm)
        .chain(mpc.into_iter().map(|p| (p, 0)))
}

/// Evidence that one owned surface is the pipe's live scanout source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanoutRunning {
    pub pipe: u8,
    /// ODM: the pipes fetching the following segments.
    pub odm: SplitPipes,
    /// MPC combine: the pipes fetching the primary's further slices.
    pub mpc: SplitPipes,
    pub stream: u8,
    /// The admitted plan whose deadlines this fetch runs under.
    pub plan: dml::Plan,
    /// GPU address the HUBP reported in use after the configuration latched.
    pub address: u64,
    /// The overlay planes blended above the primary, bottom first, each
    /// with the address its HUBP reported in use.
    pub overlays: [Option<OverlayScanout>; MAX_OVERLAYS],
    /// Two distinct frame counts sampled after the latch with no underflow.
    pub frame_before: u32,
    pub frame_after: u32,
}

/// What one HUBP/DPP/MPCC of a live scanout must show: the address it
/// fetches, whether the cursor is on, its MPCC's tree selectors (the
/// OUT_MUX of the OPP with its index, TOP, BOT, OPP_ID and UPDATE_LOCK
/// selects) and MPCC_MODE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivePipe {
    pub pipe: u8,
    pub address: u64,
    pub cursor: bool,
    pub routes: [u8; 5],
    pub mode: u8,
}

/// Each segment's MPCC tree, bottom first: the underlays' pipes for the
/// segment, the primary's (whose OPP the tree feeds), then the other
/// overlays' (normalized zpos order). An MPC-combined plane's slices sit
/// together, each further slice below the one before (its bottom_pipe, as
/// acquire_dpp_pipe_and_add_mpc_slice links it).
pub(super) fn trees(
    (pipe, odm, mpc): (u8, SplitPipes, SplitPipes),
    overlays: &[Option<OverlayScanout>; MAX_OVERLAYS],
) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    (0..odm.count() as usize)
        .map(|segment| {
            let mut tree = alloc::vec::Vec::new();
            let mut push = |pipes: &mut dyn Iterator<Item = (u8, usize)>| {
                let at = tree.len();
                for (p, s) in pipes {
                    if s == segment {
                        tree.insert(at, p);
                    }
                }
            };
            for o in overlays.iter().flatten().filter(|o| o.underlay) {
                push(&mut o.pipes());
            }
            push(&mut plane_pipes(pipe, odm, mpc));
            for o in overlays.iter().flatten().filter(|o| !o.underlay) {
                push(&mut o.pipes());
            }
            tree
        })
        .collect()
}

impl ScanoutRunning {
    /// Every pipe of this scanout as a live check finds it, mpc1_insert_plane
    /// having built each segment's tree from the top plane down: the top
    /// MPCC on the OPP's OUT_MUX, each blending over the next lower one
    /// (TOP_BOT_BLENDING), the bottom over the background (TOP_LAYER_ONLY).
    /// The cursor shows on every pipe `CursorApplied::shown` names.
    pub fn live_pipes(&self, cursor: Option<CursorApplied>) -> alloc::vec::Vec<LivePipe> {
        live_pipes(
            (self.pipe, self.odm, self.mpc),
            self.address,
            &self.overlays,
            cursor,
        )
    }
}

fn live_pipes(
    (pipe, odm, mpc): (u8, SplitPipes, SplitPipes),
    address: u64,
    overlays: &[Option<OverlayScanout>; MAX_OVERLAYS],
    cursor: Option<CursorApplied>,
) -> alloc::vec::Vec<LivePipe> {
    let mut out = alloc::vec::Vec::new();
    let opps = core::iter::once(pipe).chain(odm);
    let primary = plane_pipes(pipe, odm, mpc).fold(0u8, |m, (p, _)| m | bit(p));
    for (tree, opp) in trees((pipe, odm, mpc), overlays).into_iter().zip(opps) {
        let top = *tree.last().unwrap_or(&opp);
        for (j, &m) in tree.iter().enumerate() {
            let fetched = if primary & bit(m) != 0 {
                address
            } else {
                overlays
                    .iter()
                    .flatten()
                    .find(|o| o.pipes().any(|(p, _)| p == m))
                    .map_or(0, |o| o.address)
            };
            out.push(LivePipe {
                pipe: m,
                address: fetched,
                // dcn401_set_cursor_position runs on every pipe of the
                // stream: any plane's pipe the cursor overlaps shows it.
                cursor: cursor.is_some_and(|c| c.pipe == pipe && c.shown_on(m)),
                routes: [
                    if m == opp { top } else { 0xf },
                    m,
                    if j == 0 { 0xf } else { tree[j - 1] },
                    opp,
                    opp,
                ],
                mode: if j == 0 {
                    MPCC_MODE_TOP_ONLY as u8
                } else {
                    MPCC_MODE_TOP_BOT as u8
                },
            });
        }
    }
    out
}

/// A running timing generator's position, as Linux's get_crtc_scanoutpos
/// and get_vblank_counter read it: the 24-bit frame count (which the
/// hardware increments at the start of vsync, line 0), the scanout position
/// and the vertical blank (from `vblank_start` through the wrap to
/// `vblank_end`), with the timing it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanoutPosition {
    pub frame: u32,
    pub vpos: u32,
    pub hpos: u32,
    pub vblank_start: u32,
    pub vblank_end: u32,
    pub timing: crate::amdgpu_dml::Timing,
}

/// The vblank clock at the moment a position was read, in DRM's terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VblankPhase {
    /// Vblanks begun (frame count, 24-bit), counted at the start of vblank
    /// as DRM requires: amdgpu_get_vblank_counter_kms bumps the hardware
    /// count between vblank start and vsync.
    pub count: u32,
    /// When that vblank began and ends (scanout of the next frame starts,
    /// DRM's vblank timestamp), in ns relative to the read: start <= 0.
    pub start_ns: i64,
    pub end_ns: i64,
    pub period_ns: u64,
}

impl ScanoutPosition {
    pub fn phase(&self) -> Option<VblankPhase> {
        let t = self.timing;
        let (vt, vs, ve) = (t.v_total, self.vblank_start, self.vblank_end);
        if t.pixel_clock_khz == 0 || vt == 0 || vs > vt || ve > vs || self.vpos >= vt {
            return None;
        }
        let upper = self.vpos >= vs;
        let since = if upper {
            self.vpos - vs
        } else {
            vt - vs + self.vpos
        };
        let ns = |pixels: i64| pixels * 1_000_000 / i64::from(t.pixel_clock_khz);
        let ht = i64::from(t.h_total);
        let start = -ns(i64::from(since) * ht + i64::from(self.hpos));
        let blank = i64::from(vt - vs + ve);
        Some(VblankPhase {
            count: (self.frame + u32::from(upper)) & FRAME_MASK,
            start_ns: start,
            end_ns: start + ns(blank * ht),
            period_ns: ns(i64::from(vt) * ht) as u64,
        })
    }
}

/// What an activation or stop works on, gathered from the retained reports.
#[derive(Clone, Copy, Debug)]
pub(super) struct Pipe {
    pub(super) pipe: u8,
    /// The ODM pipes fetching the following segments, under `pipe`'s timing.
    pub(super) odm: SplitPipes,
    /// The primary's further MPC slices' pipes, on `pipe`'s OPP.
    pub(super) mpc: SplitPipes,
    pub(super) address: u64,
    /// The overlay planes above the primary, bottom first.
    pub(super) overlays: [Option<OverlayScanout>; MAX_OVERLAYS],
    pub(super) black: u32,
    pub(super) timeout_us: u64,
    /// Fail waits on underflow; cleared only while recovering from one.
    pub(super) watch: bool,
}
impl Pipe {
    /// The stream's OPPs: every ODM segment's pipe, whose OPP each tree
    /// feeds.
    pub(super) fn pipes(self) -> impl Iterator<Item = u8> + Clone {
        core::iter::once(self.pipe).chain(self.odm)
    }
    /// Every HUBP/DPP/MPCC of the scanout with the address it fetches:
    /// the primary's, then each overlay's, bottom first.
    pub(super) fn fetches(self) -> alloc::vec::Vec<(u8, u64)> {
        let mut out: alloc::vec::Vec<(u8, u64)> = plane_pipes(self.pipe, self.odm, self.mpc)
            .map(|(q, _)| (q, self.address))
            .collect();
        for o in self.overlays.iter().flatten() {
            out.extend(o.pipes().map(|(q, _)| (q, o.address)));
        }
        out
    }
    /// Every pipe of the scanout.
    pub(super) fn all_pipes(self) -> alloc::vec::Vec<u8> {
        self.fetches().into_iter().map(|(q, _)| q).collect()
    }
    /// Each segment's MPCC tree, bottom first.
    pub(super) fn trees(self) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        trees((self.pipe, self.odm, self.mpc), &self.overlays)
    }
    /// The scanout's pipes as a live check finds them (as
    /// `ScanoutRunning::live_pipes`).
    pub(super) fn live(self, cursor: Option<CursorApplied>) -> alloc::vec::Vec<LivePipe> {
        live_pipes(
            (self.pipe, self.odm, self.mpc),
            self.address,
            &self.overlays,
            cursor,
        )
    }
}

/// Last underflow observed on a live scanout, retained after the bounded
/// return to black so the cause can be diagnosed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanoutUnderflow {
    pub pipe: u8,
    pub address: u64,
    /// DCHUBP_CNTL.HUBP_UNDERFLOW_STATUS and the OPTC sticky bit as observed.
    pub hubp_status: u8,
    pub optc: bool,
    pub frame: u32,
}

impl<I: Io> Engine<I> {
    pub(super) fn dpp_control(&self, pipe: u8) -> u64 {
        self.layout.dpp(pipe, DPP_CONTROL)
    }
    fn optc_input(&self, pipe: u8) -> u64 {
        self.layout.odm(pipe, OPTC_INPUT)
    }
    /// A one-pipe tree: the pipe's MPCC (its DPP's instance) blends its DPP
    /// into its own OPP, all the pipe's instance.
    pub(super) fn routes(&self, pipe: u8, connected: bool) -> [(u64, u32); 5] {
        let l = self.layout;
        let p = l.inst_field(pipe);
        let sel = |v: u32| if connected { v } else { 0xf };
        [
            (l.out_mux(pipe), sel(p)),
            (l.mpcc(pipe, TOP), sel(p)),
            (l.mpcc(pipe, BOTTOM), 0xf),
            (l.mpcc(pipe, OPP_ID), sel(p)),
            (l.mpcc(pipe, UPDATE_LOCK), sel(p)),
        ]
    }
    fn underflow(&mut self, pipe: u8) -> Result<(), Error> {
        for p in self.plane_pipes(pipe) {
            let at = self.layout.hubp(p, HUBP_CONTROL);
            if self.read(at)? & HUBP_UNDERFLOW != 0 {
                return Err(Error::Underflow(at));
            }
        }
        let at = self.optc_input(pipe);
        if self.read(at)? & OPTC_UNDERFLOW != 0 {
            return Err(Error::Underflow(at));
        }
        Ok(())
    }
    /// No transaction of this OTG may still be pending or locked; Linux's
    /// dcn30_wait_for_all_pending_updates precondition, checked rather than
    /// waited for because this owner alone writes the pipe.
    fn quiet(&mut self, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask, value) in [
            (l.otg(pipe, CONTROL), OTG_MASTER_EN, OTG_MASTER_EN),
            (l.otg(pipe, LOCK), LOCK_REQUEST | LOCK_STATUS, 0),
            (l.otg(pipe, DOUBLE_BUFFER), OTG_UPDATE_PENDING, 0),
            (l.otg(pipe, PIPE_UPDATE), PIPE_PENDING, 0),
            (self.optc_input(pipe), OPTC_PENDING, 0),
            (l.otg(pipe, GSL), 0x8000_000f, 0),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Busy);
            }
        }
        let pipes: alloc::vec::Vec<u8> = self.fetch_pipes(pipe).collect();
        for p in pipes {
            if self.read(l.opp(p, DPG_PENDING))? & 1 != 0 {
                return Err(Error::Busy);
            }
        }
        for p in self.plane_pipes(pipe) {
            if self.read(l.mpcc(p, UPDATE_LOCK))? & 0x70 != 0 {
                return Err(Error::Busy);
            }
        }
        self.underflow(pipe)
    }
    /// Fetch stopped exactly as staged: blank and drained HUBP with its clock
    /// gated, DPP clock gated, all routes detached and the DPG showing black.
    fn staged(&mut self, p: Pipe) -> Result<(), Error> {
        let l = self.layout;
        for q in p.pipes() {
            if self.read(l.opp(q, DPG))? & DPG_FIELDS != p.black {
                return Err(Error::Readback(l.opp(q, DPG)));
            }
        }
        for (q, address) in p.fetches() {
            for (at, mask, value) in [
                (
                    l.hubp(q, HUBP_CONTROL),
                    BLANK_EN | NO_OUTSTANDING | TTU_DISABLE,
                    3,
                ),
                (l.hubp(q, HUBP_CLOCK), 1, 0),
                (self.dpp_control(q), DPP_CLOCK_ENABLE, 0),
                (l.mpcc(q, MPCC_CONTROL), 3, MPCC_MODE_TOP_ONLY),
                (l.hubp(q, CURSOR), CURSOR_REQ_MODE | 1, CURSOR_REQ_MODE),
                (l.hubp(q, ADDRESS), u32::MAX, address as u32),
                (l.hubp(q, ADDRESS_HIGH), 0xffff, (address >> 32) as u32),
            ] {
                if self.read(at)? & mask != value {
                    return Err(Error::Readback(at));
                }
            }
            for (at, value) in self.routes(q, false) {
                if self.read(at)? & 0xf != value {
                    return Err(Error::Readback(at));
                }
            }
        }
        Ok(())
    }
    pub(super) async fn lock(&mut self, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        // optc1_lock: OTG_MASTER_UPDATE_LOCK_SEL = optc->inst.
        self.update(
            l.otg(pipe, GLOBAL_CONTROL2),
            LOCK_SELECT,
            l.inst_field(pipe) << 25,
        )?;
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, LOCK_REQUEST)?;
        // Linux waits only 10 us and proceeds; here the lock must be held.
        self.wait(l.otg(pipe, LOCK), LOCK_STATUS, LOCK_STATUS, 1000)
            .await
    }
    /// The OTG's double-buffered registers latched after an unlocked update.
    pub(super) async fn stream_latched(&mut self, p: Pipe) -> Result<(), Error> {
        let l = self.layout;
        self.latched(p, |e| {
            for (at, mask) in [
                (l.otg(p.pipe, DOUBLE_BUFFER), OTG_UPDATE_PENDING),
                (l.otg(p.pipe, PIPE_UPDATE), PIPE_PENDING),
            ] {
                if e.read(at)? & mask != 0 {
                    return Ok(Some(at));
                }
            }
            Ok(None)
        })
        .await
    }
    pub(super) async fn latched(
        &mut self,
        p: Pipe,
        mut done: impl FnMut(&mut Self) -> Result<Option<u64>, Error>,
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_us(p.timeout_us);
        #[cfg(feature = "kernel-test")]
        let mut polls = self.io.wait_poll_limit();
        loop {
            if p.watch {
                self.underflow(p.pipe)?;
            }
            match done(self)? {
                None => return Ok(()),
                #[cfg(feature = "kernel-test")]
                Some(at) if polls.is_some() => {
                    let left = polls.as_mut().unwrap();
                    if *left == 0 {
                        return Err(Error::Timeout(at));
                    }
                    *left -= 1;
                    narf_scheduler::yield_now().await;
                    continue;
                }
                Some(at) if deadline.expired() => return Err(Error::Timeout(at)),
                Some(_) => {}
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(10).as_instant()).await;
        }
    }
    pub(super) async fn fresh_frames(&mut self, p: Pipe) -> Result<(u32, u32), Error> {
        let at = self.layout.otg(p.pipe, FRAME_COUNT);
        let before = self.read(at)? & FRAME_MASK;
        let mut seen = 0;
        let mut last = before;
        self.latched(p, |e| {
            let now = e.read(at)? & FRAME_MASK;
            if now != last {
                seen += 1;
                last = now;
            }
            Ok((seen < 2).then_some(at))
        })
        .await?;
        Ok((before, last))
    }
    /// No flip pending and EARLIEST_INUSE reporting `address`, or the
    /// register still waiting.
    fn in_use(&mut self, pipe: u8, address: u64) -> Result<Option<u64>, Error> {
        let l = self.layout;
        let flip = self.read(l.hubp(pipe, FLIP))?;
        let low = self.read(l.hubp(pipe, EARLIEST_INUSE))?;
        let high = self.read(l.hubp(pipe, EARLIEST_INUSE_HIGH))? & 0xffff;
        Ok(
            (flip & FLIP_PENDING != 0 || u64::from(high) << 32 | u64::from(low) != address)
                .then_some(l.hubp(pipe, EARLIEST_INUSE)),
        )
    }
    /// A live pipe may flip only with no transaction of its own outstanding.
    pub(super) fn flip_quiet(&mut self, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask) in [
            (l.otg(pipe, LOCK), LOCK_REQUEST | LOCK_STATUS),
            (l.otg(pipe, DOUBLE_BUFFER), OTG_UPDATE_PENDING),
            (l.otg(pipe, PIPE_UPDATE), PIPE_PENDING),
        ] {
            if self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        for q in self.plane_pipes(pipe) {
            if self.read(l.hubp(q, FLIP))? & FLIP_PENDING != 0
                || self.read(l.mpcc(q, UPDATE_LOCK))? & 0x70 != 0
            {
                return Err(Error::Busy);
            }
        }
        self.underflow(pipe)
    }
    /// `in_use` for every pipe of the scanout at the address it fetches:
    /// the first still waiting.
    pub(super) fn all_in_use(&mut self, p: Pipe) -> Result<Option<u64>, Error> {
        for (q, address) in p.fetches() {
            if let Some(at) = self.in_use(q, address)? {
                return Ok(Some(at));
            }
        }
        Ok(None)
    }
    /// Re-address the live fetch under the master-update lock (a VSYNC flip:
    /// the staged flip type is 0) and wait for the HUBP to report the new
    /// surface in use, without underflow. Returns the frame count then.
    /// Every plane of `p` whose address differs from `from`'s flips; all of
    /// them latch at the one VUPDATE the lock releases to.
    #[cfg(feature = "kernel-test")]
    pub(super) async fn flip_to(&mut self, p: Pipe) -> Result<u32, Error> {
        self.flip_from(p, None).await
    }
    /// The surface HUBP `q` fetches (its own or, as an ODM segment's or
    /// MPC slice's pipe, its plane's), as its records name it.
    pub(super) fn fetched_surface(&self, q: u8) -> Option<SurfaceApplied> {
        self.status
            .surfaces
            .iter()
            .flatten()
            .find(|a| a.request.pipe_mask() & bit(q) != 0)
            .copied()
    }
    /// The chroma plane's offset of the 4:2:0 surface HUBP `q` fetches;
    /// none for RGB.
    fn chroma_offset(&self, q: u8) -> Option<u64> {
        self.fetched_surface(q)
            .and_then(|a| a.chroma)
            .map(|(offset, _)| offset)
    }
    /// hubp401_program_size for HUBP `q` when the surface its records name
    /// fetches with another pitch than the one programmed: a flip between a
    /// staged buffer and a client framebuffer of another pitch (DC's MED
    /// plane_size update, programmed under the same lock as the address).
    /// Nothing is written while the pitches agree (a FAST flip).
    fn write_fetch_pitch(&mut self, q: u8) -> Result<(), Error> {
        let Some(a) = self.fetched_surface(q) else {
            return Ok(());
        };
        let l = self.layout;
        let format = a.request.format;
        let mut pitches = alloc::vec![(PITCH, a.pitch_bytes / format.bytes_per_pixel() - 1)];
        if let Some((_, pitch_c)) = a.chroma {
            pitches.push((PITCH_C, pitch_c / format.chroma_bytes_per_pixel() - 1));
        }
        for (r, value) in pitches {
            let at = l.hubp(q, r);
            if self.read(at)? & 0xffff != value {
                self.update(at, 0xffff, value)?;
            }
        }
        Ok(())
    }
    /// hubp401_program_surface_flip_and_addr's address writes for HUBP `q`
    /// fetching a surface at `address`: a 4:2:0 surface's chroma first, then
    /// the luma (or RGB) address, each high half before the low one, whose
    /// write latches the flip.
    pub(super) fn write_fetch_address(&mut self, q: u8, address: u64) -> Result<(), Error> {
        let l = self.layout;
        if let Some(offset) = self.chroma_offset(q) {
            let c = address + offset;
            self.update(l.hubp(q, ADDRESS_HIGH_C), 0xffff, (c >> 32) as u32)?;
            self.update(l.hubp(q, ADDRESS_C), u32::MAX, c as u32)?;
        }
        self.update(l.hubp(q, ADDRESS_HIGH), 0xffff, (address >> 32) as u32)?;
        self.update(l.hubp(q, ADDRESS), u32::MAX, address as u32)
    }
    /// `flip_to`, re-addressing only the planes whose address differs from
    /// `from`'s (all of them without one).
    pub(super) async fn flip_from(&mut self, p: Pipe, from: Option<Pipe>) -> Result<u32, Error> {
        let l = self.layout;
        let pipe = p.pipe;
        self.lock(pipe).await?;
        // Both ODM halves of every flipping plane re-address under the one
        // master lock.
        let old = from.map(Pipe::fetches);
        for (i, (q, address)) in p.fetches().into_iter().enumerate() {
            if old
                .as_ref()
                .is_some_and(|o| o.get(i) == Some(&(q, address)))
            {
                continue;
            }
            self.write_fetch_pitch(q)?;
            self.write_fetch_address(q, address)?;
        }
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, 0)?;
        // Unlocked: under DRR the manual trigger ends the stretched blank.
        self.drr_trigger(pipe)?;
        self.latched(p, |e| e.all_in_use(p)).await?;
        Ok(self.read(l.otg(pipe, FRAME_COUNT))? & FRAME_MASK)
    }
    /// The MPCC tree writes of one segment, as mpc1_insert_plane makes them
    /// for its planes inserted from the top down, each at the bottom: the
    /// new MPCC alone at the bottom over the background (TOP_LAYER_ONLY),
    /// the one above it then blending over it (TOP_BOT_BLENDING), the first
    /// (top) one on the OPP's OUT_MUX. `opp` and `tree` are pipe indices;
    /// the selectors take instances (MPCC_TOP_SEL = dpp_id, MPCC_OPP_ID =
    /// opp_id, MPC_OUT_MUX = mpcc_id = dpp->inst).
    fn insert_tree(&mut self, opp: u8, tree: &[u8]) -> Result<(), Error> {
        let l = self.layout;
        let mut above: Option<u8> = None;
        for &m in tree.iter().rev() {
            self.update(l.mpcc(m, BOTTOM), 0xf, 0xf)?;
            self.update(l.mpcc(m, MPCC_CONTROL), 3, MPCC_MODE_TOP_ONLY)?;
            self.update(l.mpcc(m, TOP), 0xf, l.inst_field(m))?;
            self.update(l.mpcc(m, OPP_ID), 0xf, l.inst_field(opp))?;
            self.update(l.mpcc(m, UPDATE_LOCK), 0xf, l.inst_field(opp))?;
            match above {
                None => self.update(l.out_mux(opp), 0xf, l.inst_field(m))?,
                Some(a) => {
                    self.update(l.mpcc(a, BOTTOM), 0xf, l.inst_field(m))?;
                    self.update(l.mpcc(a, MPCC_CONTROL), 3, MPCC_MODE_TOP_BOT)?;
                }
            }
            above = Some(m);
        }
        Ok(())
    }
    /// Connect and unblank under one OTG master-update lock so DPG release,
    /// MPCC insertion, address and HUBP unblank latch at the same VUPDATE.
    pub(super) async fn start_fetch(&mut self, p: Pipe) -> Result<(u32, u32), Error> {
        let l = self.layout;
        let pipe = p.pipe;
        let hubbub = |r: u64| l.base + r * 4;
        // Clocks first, while blanked and detached; Linux never has them gated
        // on a live plane.
        for q in p.all_pipes() {
            self.update(l.hubp(q, HUBP_CLOCK), 1, 1)?;
            self.update(self.dpp_control(q), DPP_CLOCK_ENABLE, DPP_CLOCK_ENABLE)?;
            self.wait(l.hubp(q, HUBP_CONTROL), 0x1007, 3, 100_000)
                .await?;
        }
        self.lock(pipe).await?;
        // dcn401_program_front_end_for_ctx forces P-state off across 0->1.
        self.update(hubbub(DRAM_STATE), PSTATE_FORCE, PSTATE_DISALLOWED)?;
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(500).as_instant()).await;
        // dcn401_program_pipe's color for an enabled pipe: CRTC color under
        // the same lock, latching with the plane.
        self.program_color(p).await?;
        // Each ODM segment's OPP, MPCC tree and HUBPs under the one master
        // lock: they latch together at the combined timing's VUPDATE.
        for q in p.pipes() {
            self.update(l.opp(q, DPG), DPG_FIELDS, 0)?; // video mode
        }
        for (tree, opp) in p.trees().into_iter().zip(p.pipes()) {
            self.insert_tree(opp, &tree)?;
        }
        for (q, address) in p.fetches() {
            // Re-arm the flip: high half first, the low write publishes it.
            self.write_fetch_address(q, address)?;
            self.update(l.hubp(q, HUBP_CONTROL), BLANK_EN | TTU_DISABLE, 0)?;
        }
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, 0)?;
        // dcn401_post_unlock_program_front_end: the new surface is in use only
        // when no flip is pending and EARLIEST_INUSE reports its address. A
        // requested-address readback is not that evidence.
        self.latched(p, |e| {
            if let Some(at) = e.all_in_use(p)? {
                return Ok(Some(at));
            }
            for (at, mask, value) in [
                (l.otg(pipe, DOUBLE_BUFFER), OTG_UPDATE_PENDING, 0),
                (l.otg(pipe, PIPE_UPDATE), PIPE_PENDING, 0),
            ] {
                if e.read(at)? & mask != value {
                    return Ok(Some(at));
                }
            }
            for q in p.pipes() {
                for (at, mask, value) in [(l.opp(q, DPG_PENDING), 1, 0), (l.opp(q, DPG), DPG_EN, 0)]
                {
                    if e.read(at)? & mask != value {
                        return Ok(Some(at));
                    }
                }
            }
            for q in p.all_pipes() {
                let at = l.mpcc(q, MPC_STATUS); // MPCC no longer DISABLED
                if e.read(at)? & 4 != 0 {
                    return Ok(Some(at));
                }
            }
            Ok(None)
        })
        .await?;
        self.update(hubbub(DRAM_STATE), PSTATE_FORCE, 0)?;
        for live in p.live(None) {
            self.tree_routes(live)?;
            let at = l.hubp(live.pipe, HUBP_CONTROL);
            if self.read(at)? & (BLANK_EN | TTU_DISABLE) != 0 {
                return Err(Error::Readback(at));
            }
        }
        self.fresh_frames(p).await
    }
    /// Black first, detach under the lock, then drain and blank the HUBPs and
    /// gate their clocks only after the MPCCs and memory requests are idle.
    /// Every MPCC leaves the tree at once (mpc1_remove_mpcc for each plane,
    /// the overlays first), back to its staged TOP_LAYER_ONLY mode.
    pub(super) async fn stop_fetch(&mut self, p: Pipe) -> Result<(), Error> {
        let l = self.layout;
        let pipe = p.pipe;
        // Leaving scanout returns to fixed refresh, so the later video and
        // timing waits see nominal frames; `p` already bounds a stretched one.
        self.drr_fixed(pipe)?;
        // The cursor is a fetch source too; it latches off with the black.
        self.hide_cursor(pipe)?;
        self.lock(pipe).await?;
        for q in p.pipes() {
            self.update(l.opp(q, DPG), DPG_FIELDS, p.black)?;
        }
        let mut detach = p.all_pipes();
        detach.reverse();
        for &q in &detach {
            for (at, value) in self.routes(q, false) {
                self.update(at, 0xf, value)?;
            }
            self.update(l.mpcc(q, MPCC_CONTROL), 3, MPCC_MODE_TOP_ONLY)?;
        }
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, 0)?;
        // Black must be on screen before the MPCC may report disconnection.
        self.latched(p, |e| {
            let at = l.otg(pipe, DOUBLE_BUFFER);
            if e.read(at)? & OTG_UPDATE_PENDING != 0 {
                return Ok(Some(at));
            }
            for q in p.pipes() {
                for (at, mask, value) in [
                    (l.opp(q, DPG_PENDING), 1, 0),
                    (l.opp(q, DPG), DPG_FIELDS, p.black),
                ] {
                    if e.read(at)? & mask != value {
                        return Ok(Some(at));
                    }
                }
            }
            for &q in &detach {
                // mpc2_assert_idle_mpcc: DISABLED, or IDLE and not BUSY.
                let at = l.mpcc(q, MPC_STATUS);
                let status = e.read(at)?;
                if status & 2 != 0 || status & 5 == 0 {
                    return Ok(Some(at));
                }
            }
            Ok(None)
        })
        .await?;
        for &q in &detach {
            // hubp2_set_blank(true): no outstanding requests before blanking.
            self.wait(
                l.hubp(q, HUBP_CONTROL),
                NO_OUTSTANDING,
                NO_OUTSTANDING,
                100_000,
            )
            .await?;
            self.update(l.hubp(q, HUBP_CONTROL), BLANK_EN | TTU_DISABLE, BLANK_EN)?;
            self.wait(l.hubp(q, HUBP_CONTROL), 0x1007, 3, 100_000)
                .await?;
            self.update(l.hubp(q, HUBP_CLOCK), 1, 0)?;
            self.update(self.dpp_control(q), DPP_CLOCK_ENABLE, 0)?;
        }
        self.staged(p)
    }
    /// The owned scanout as `start_fetch` left it: unblanked fetch of each
    /// plane's surface, clocks on, trees connected, DPG released, the cursor
    /// as recorded.
    /// The primary's pipes fetch `address`; the overlays are the recorded
    /// live scanout's.
    pub(in crate::amdgpu_dcn401_otg) fn live_fetch(
        &mut self,
        pipe: u8,
        address: u64,
    ) -> Result<(), Error> {
        let (odm, mpc) = self
            .status
            .surfaces
            .get(usize::from(pipe))
            .copied()
            .flatten()
            .map_or((SplitPipes::NONE, SplitPipes::NONE), |a| {
                (a.request.odm, a.request.mpc)
            });
        let overlays = self
            .status
            .scanout
            .filter(|s| s.pipe == pipe)
            .map_or([None; MAX_OVERLAYS], |s| s.overlays);
        for live in live_pipes((pipe, odm, mpc), address, &overlays, self.status.cursor) {
            self.live_pipe(live)?;
        }
        Ok(())
    }
    /// One pipe of a single-plane live scanout, its own tree's only MPCC.
    #[cfg(feature = "kernel-test")]
    pub(in crate::amdgpu_dcn401_otg) fn live_segment(
        &mut self,
        pipe: u8,
        address: u64,
        cursor: bool,
    ) -> Result<(), Error> {
        self.live_pipe(LivePipe {
            pipe,
            address,
            cursor,
            routes: [pipe, pipe, 0xf, pipe, pipe],
            mode: MPCC_MODE_TOP_ONLY as u8,
        })
    }
    /// One pipe's MPCC tree selectors, and in a tree of several planes its
    /// MPCC_MODE (a single plane's is the staged TOP_LAYER_ONLY, which
    /// connection leaves alone).
    fn tree_routes(&mut self, live: LivePipe) -> Result<(), Error> {
        let l = self.layout;
        let q = live.pipe;
        // `routes` names pipes; the selectors hold their instances.
        let [mux, top, bot, opp, lock] =
            live.routes
                .map(|r| if r == 0xf { 0xf } else { l.inst_field(r) });
        for (at, value) in [
            (l.out_mux(q), mux),
            (l.mpcc(q, TOP), top),
            (l.mpcc(q, BOTTOM), bot),
            (l.mpcc(q, OPP_ID), opp),
            (l.mpcc(q, UPDATE_LOCK), lock),
        ] {
            if self.read(at)? & 0xf != value {
                return Err(Error::Readback(at));
            }
        }
        let stacked = live.routes[2] != 0xf || live.routes[0] != q;
        let at = l.mpcc(q, MPCC_CONTROL);
        if stacked && self.read(at)? & 3 != u32::from(live.mode) {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    /// One HUBP/DPP/MPCC (with its OPP's DPG when it is the tree's OPP) of a
    /// live scanout. Also what another display's live pipes are checked
    /// against (each on its own).
    pub(in crate::amdgpu_dcn401_otg) fn live_pipe(&mut self, live: LivePipe) -> Result<(), Error> {
        let l = self.layout;
        let (pipe, address) = (live.pipe, live.address);
        for (at, mask, value) in [
            (l.hubp(pipe, HUBP_CONTROL), BLANK_EN | 4 | TTU_DISABLE, 0),
            (l.hubp(pipe, HUBP_CLOCK), 1, 1),
            (self.dpp_control(pipe), DPP_CLOCK_ENABLE, DPP_CLOCK_ENABLE),
            (l.mpcc(pipe, MPC_STATUS), 4, 0),
            (l.hubp(pipe, CURSOR), 1, u32::from(live.cursor)),
            (l.hubp(pipe, ADDRESS), u32::MAX, address as u32),
            (l.hubp(pipe, ADDRESS_HIGH), 0xffff, (address >> 32) as u32),
            (l.hubp(pipe, EARLIEST_INUSE), u32::MAX, address as u32),
            (
                l.hubp(pipe, EARLIEST_INUSE_HIGH),
                0xffff,
                (address >> 32) as u32,
            ),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        if live.routes[3] == pipe && self.read(l.opp(pipe, DPG))? & DPG_FIELDS != 0 {
            return Err(Error::Readback(l.opp(pipe, DPG)));
        }
        self.tree_routes(live)
    }
    /// Record an underflow, return the pipe to black through the normal stop
    /// sequence without failing on the (sticky) status, then clear it. Linux
    /// hubp2_clear_underflow/optc1_clear_optc_underflow are single strobes.
    pub(super) async fn recover_fetch(&mut self, p: Pipe) -> Result<ScanoutUnderflow, Error> {
        let l = self.layout;
        let mut hubp = 0;
        for q in p.all_pipes() {
            hubp |= self.read(l.hubp(q, HUBP_CONTROL))?;
        }
        let optc = self.read(self.optc_input(p.pipe))?;
        let report = ScanoutUnderflow {
            pipe: p.pipe,
            address: p.address,
            hubp_status: ((hubp & HUBP_UNDERFLOW) >> 28) as u8,
            optc: optc & OPTC_UNDERFLOW != 0,
            frame: self.read(l.otg(p.pipe, FRAME_COUNT))? & FRAME_MASK,
        };
        self.stop_fetch(Pipe { watch: false, ..p }).await?;
        let clears = p
            .all_pipes()
            .into_iter()
            .map(|q| (l.hubp(q, HUBP_CONTROL), HUBP_UNDERFLOW_CLEAR))
            .chain([(self.optc_input(p.pipe), OPTC_UNDERFLOW_CLEAR)]);
        for (at, clear) in clears {
            let old = self.read(at)?;
            self.access(|io| {
                io.write(at, old | clear);
                Ok(())
            })?;
        }
        // With fetch blanked a cleared underflow must stay clear.
        self.underflow(p.pipe)?;
        self.staged(p)?;
        Ok(report)
    }
}

/// What recovery must re-establish: the stream to return to and the owners
/// the deadlines were bound to.
#[derive(Clone, Copy)]
struct Context {
    stream: u8,
    deadlines: DeadlinesApplied,
    crystal_khz: u32,
    current: (dccg::Applied, DisplayContext),
}

impl Surfaces {
    /// Current owners must still be exactly the ones the deadlines were
    /// programmed for, and every staged register must still hold its value.
    pub(super) fn scanout_bound<I: Io>(
        &self,
        e: &mut Engine<I>,
        d: DeadlinesApplied,
        crystal_khz: u32,
        current: (dccg::Applied, DisplayContext),
    ) -> Result<Pipe, Error> {
        self.scanout_bound_with(e, d, crystal_khz, current, WatermarkUpdate::Exact)
    }
    /// `scanout_bound` with the shared watermarks checked as `wm` would
    /// have written them: exactly, or (while a configuration change raised
    /// them for another display's new plan) at least this plan's.
    pub(super) fn scanout_bound_with<I: Io>(
        &self,
        e: &mut Engine<I>,
        d: DeadlinesApplied,
        crystal_khz: u32,
        (clock, config): (dccg::Applied, DisplayContext),
        wm: WatermarkUpdate,
    ) -> Result<Pipe, Error> {
        let slot = usize::from(d.pipe);
        let a = e.status.requestor.ok_or(Error::Invalid)?;
        let mpc = e.status.mpcs[slot].ok_or(Error::Invalid)?;
        let blank = e.status.blanks[slot].ok_or(Error::Invalid)?;
        let surface = self
            .0
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?
            .applied;
        if a.pipe != d.pipe
            || a.surface != surface
            || mpc.dpp.surface != surface
            || e.status.surfaces[slot] != Some(surface)
            || e.status.dpps[slot] != Some(mpc.dpp)
            || mpc.dpp.timing != blank.timing
            || e.status.pipes[slot].map(|p| p.request) != Some(blank.timing.request)
        {
            return Err(Error::Invalid);
        }
        e.verify_surface(surface)?;
        e.verify_memory(d.pipe, config)?;
        e.verify_mpc(mpc)?;
        // Each overlay's records name its surface and the same stream.
        for o in a.overlays.iter().flatten() {
            let slot = usize::from(o.request.pipe);
            let staged = self.0.get(slot).and_then(Option::as_ref).map(|s| s.applied);
            let m = e.status.mpcs[slot].ok_or(Error::Invalid)?;
            if staged != Some(*o)
                || e.status.surfaces[slot] != Some(*o)
                || e.status.dpps[slot] != Some(m.dpp)
                || m.dpp.surface != *o
                || m.dpp.timing != blank.timing
            {
                return Err(Error::Invalid);
            }
            e.verify_surface(*o)?;
            e.verify_memory(o.request.pipe, config)?;
            e.verify_mpc(m)?;
        }
        e.verify_live_requestor(d.pipe)?;
        e.deadline_writes_with(d.pipe, &d.plan, true, wm)?;
        let refclk = e.dchub_refclk_khz(crystal_khz)?;
        if !deadline::bound(&d.plan, blank.timing.request, a, clock, refclk) {
            return Err(Error::Invalid);
        }
        Ok(Pipe {
            pipe: d.pipe,
            odm: surface.request.odm,
            mpc: surface.request.mpc,
            address: surface.address,
            overlays: a.overlays.map(|o| o.map(OverlayScanout::of)),
            black: 0x41 | blank.request.depth.dpg() << 12,
            timeout_us: e.frame_timeout_us(d.pipe, blank)?,
            watch: true,
        })
    }
    pub(in crate::amdgpu_dcn401_otg) async fn start_scanout<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        crystal_khz: u32,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<ScanoutRunning, Error> {
        let (stream, video_pipe) = e.running_video()?;
        let d = e.status.deadlines.ok_or(Error::Invalid)?;
        if d.pipe != pipe || video_pipe != pipe {
            return Err(Error::Invalid);
        }
        let current = owners()?;
        let p = self.scanout_bound(e, d, crystal_khz, current)?;
        let ctx = Context {
            stream,
            deadlines: d,
            crystal_khz,
            current,
        };
        e.quiet(pipe)?;
        e.staged(p)?;
        e.requestor_errors(pipe)?;
        // From the first write on, cancellation or failure quarantines the pipe.
        e.status.state = State::StartingScanout(pipe);
        let result = async {
            let frames = e.start_fetch(p).await?;
            if owners()? != current {
                return Err(Error::Busy);
            }
            Ok(frames)
        }
        .await;
        match result {
            Ok((frame_before, frame_after)) => {
                let report = ScanoutRunning {
                    pipe,
                    odm: p.odm,
                    mpc: p.mpc,
                    stream,
                    plan: d.plan,
                    address: p.address,
                    overlays: p.overlays,
                    frame_before,
                    frame_after,
                };
                e.status.scanout = Some(report);
                e.status.state = State::ScanoutRunning(pipe);
                Ok(report)
            }
            Err(err) => Err(self.recover(e, p, ctx, &mut owners, err).await),
        }
    }
    /// Underflow is the one failure with a proven way back to black; any other
    /// failure, or a recovery that does not complete, quarantines the pipe.
    async fn recover<I: Io>(
        &self,
        e: &mut Engine<I>,
        p: Pipe,
        ctx: Context,
        owners: &mut impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
        err: Error,
    ) -> Error {
        if !matches!(err, Error::Underflow(_)) {
            e.status.state = State::Failed(err);
            return err;
        }
        e.status.state = State::StoppingScanout(p.pipe);
        let result = async {
            let report = e.recover_fetch(p).await?;
            e.status.underflow = Some(report);
            if owners()? != ctx.current {
                return Err(Error::Busy);
            }
            self.scanout_bound(e, ctx.deadlines, ctx.crystal_khz, ctx.current)
        }
        .await;
        e.status.state = match result {
            Ok(_) => {
                e.status.scanout = None;
                e.status.cursor = None;
                e.video_state(ctx.stream)
            }
            Err(failed) => State::Failed(failed),
        };
        err
    }
    /// Read-only health check of a live scanout. Underflow returns the pipe to
    /// black and retains `Status::underflow`; other mismatches are reported
    /// without writes and leave the decision to stop to the caller.
    pub(in crate::amdgpu_dcn401_otg) async fn check_scanout<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        crystal_khz: u32,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<u32, Error> {
        let running = e.status.scanout.ok_or(Error::Invalid)?;
        if e.status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
            return Err(Error::Busy);
        }
        let deadlines = e.status.deadlines.ok_or(Error::Invalid)?;
        let current = owners()?;
        let p = self.scanout_bound(e, deadlines, crystal_khz, current)?;
        if p.address != running.address
            || p.overlays != running.overlays
            || deadlines.plan != running.plan
        {
            return Err(Error::Invalid);
        }
        match e.underflow(pipe) {
            Err(err @ Error::Underflow(_)) => {
                let ctx = Context {
                    stream: running.stream,
                    deadlines,
                    crystal_khz,
                    current,
                };
                return Err(self.recover(e, p, ctx, &mut owners, err).await);
            }
            other => other?,
        }
        e.video_verify_scanout(running)?;
        Ok(e.read(e.layout.otg(pipe, FRAME_COUNT))? & FRAME_MASK)
    }
    pub(in crate::amdgpu_dcn401_otg) async fn stop_scanout<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        crystal_khz: u32,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<(), Error> {
        let running = e.status.scanout.ok_or(Error::Invalid)?;
        if e.status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
            return Err(Error::Busy);
        }
        let d = e.status.deadlines.ok_or(Error::Invalid)?;
        let current = owners()?;
        let p = self.scanout_bound(e, d, crystal_khz, current)?;
        if p.address != running.address || p.overlays != running.overlays {
            return Err(Error::Invalid);
        }
        e.status.state = State::StoppingScanout(pipe);
        let result = async {
            e.stop_fetch(p).await?;
            if owners()? != current {
                return Err(Error::Busy);
            }
            self.scanout_bound(e, d, crystal_khz, current).map(|_| ())
        }
        .await;
        match result {
            Ok(()) => {
                e.status.scanout = None;
                e.status.cursor = None;
                e.status.state = e.video_state(running.stream);
                Ok(())
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}
impl<I: Io> Engine<I> {
    /// The stream and pipe of the black video a scanout may start on: DP SST
    /// or TMDS HDMI, whichever owner is current.
    pub(in crate::amdgpu_dcn401_otg) fn running_video(&self) -> Result<(u8, u8), Error> {
        let s = &self.status;
        match s.state {
            State::DpVideoRunning(stream) => {
                let v = s.dp_video_running.ok_or(Error::Invalid)?;
                if v.frontend.request.stream != stream {
                    return Err(Error::Invalid);
                }
                Ok((stream, v.timing.blank.request.pipe))
            }
            State::HdmiVideoRunning(stream) => {
                let v = s.hdmi_video_running.ok_or(Error::Invalid)?;
                if v.link.request.stream != stream {
                    return Err(Error::Invalid);
                }
                Ok((stream, v.timing.blank.request.pipe))
            }
            State::UhbrVideoRunning(stream) => {
                let v = s.uhbr_video_running.ok_or(Error::Invalid)?;
                if v.stream != stream {
                    return Err(Error::Invalid);
                }
                Ok((stream, v.timing.blank.request.pipe))
            }
            // The single HPO FRL stream is named by its pipe.
            State::FrlVideoRunning(pipe) => {
                let v = s.frl_video_running.ok_or(Error::Invalid)?;
                if v.request.pipe != pipe {
                    return Err(Error::Invalid);
                }
                Ok((pipe, pipe))
            }
            // No video record at all is a missing predecessor, not contention.
            _ if s.dp_video_running.is_none()
                && s.hdmi_video_running.is_none()
                && s.uhbr_video_running.is_none()
                && s.frl_video_running.is_none() =>
            {
                Err(Error::Invalid)
            }
            _ => Err(Error::Busy),
        }
    }
    /// The video state a stopped (or underflow-recovered) scanout returns to.
    fn video_state(&self, stream: u8) -> State {
        if self
            .status
            .hdmi_video_running
            .is_some_and(|v| v.link.request.stream == stream)
        {
            State::HdmiVideoRunning(stream)
        } else if self
            .status
            .uhbr_video_running
            .is_some_and(|v| v.stream == stream)
        {
            State::UhbrVideoRunning(stream)
        } else if self
            .status
            .frl_video_running
            .is_some_and(|v| v.request.pipe == stream)
        {
            State::FrlVideoRunning(stream)
        } else {
            State::DpVideoRunning(stream)
        }
    }
    fn video_verify_scanout(&mut self, live: ScanoutRunning) -> Result<(), Error> {
        if self.status.hdmi_video_running.is_some() {
            self.hdmi_video_verify_scanout(live)
        } else if let Some(v) = self.status.frl_video_running {
            if v.request.pipe != live.pipe || live.stream != live.pipe {
                return Err(Error::Invalid);
            }
            self.frl_video_verify_running(&v)
        } else if let Some(v) = self.status.uhbr_video_running {
            if v.stream != live.stream || v.timing.blank.request.pipe != live.pipe {
                return Err(Error::Invalid);
            }
            self.uhbr_video_verify_running(&v)
        } else {
            self.dp_video_verify_scanout(live)
        }
    }
}
impl Surfaces {
    /// CPU view of the live scanout: bus-physical BAR address of the owned
    /// surface, its visible size and byte pitch, for console adoption.
    pub(in crate::amdgpu_dcn401_otg) fn scanout_framebuffer(
        &self,
        status: &Status,
        pipe: u8,
    ) -> Result<GenericFb, Error> {
        let running = status.scanout.ok_or(Error::Invalid)?;
        if status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
            return Err(Error::Busy);
        }
        let surface = self
            .0
            .get(usize::from(pipe))
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        let a = surface.applied;
        if a.address != running.address || a.request.format != SurfaceFormat::Xrgb8888 {
            return Err(Error::Invalid);
        }
        // A client framebuffer scanned out in place has no CPU view here:
        // the console never draws into it.
        if a.address != surface.memory.address() {
            return Err(Error::Busy);
        }
        Ok(GenericFb::new(
            surface.memory.mapping().phys.raw(),
            a.request.width,
            a.request.height,
            a.pitch_bytes,
            32,
        ))
    }
}
impl Otg {
    /// Make the staged surface the visible scanout source of a pipe whose
    /// legacy DP SST stream already carries black video, after re-binding the
    /// programmed deadlines to the current owners. Success means the HUBP
    /// reported the surface in use and two fresh frames ran without underflow.
    /// # Safety
    /// The surface must hold the intended image and stay allocated until a
    /// successful stop. Exclude firmware/FAMS and concurrent display/hub/VM/
    /// IRQ/clock/reset/power writers; retain everything on failure or
    /// cancellation, which quarantines the pipe.
    pub async unsafe fn start_scanout(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        crystal_khz: u32,
    ) -> Result<ScanoutRunning, Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        let regs = self.0.io.0;
        self.1
            .start_scanout(&mut self.0, pipe, crystal_khz, || {
                Ok((
                    dccg.retained_timing_clock(regs, clocks, pipe)
                        .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
    /// Re-verify a live scanout and its stream against the current owners and
    /// return the frame count. An underflow returns the pipe to black video
    /// (state `DpVideoRunning`, diagnostics in `Status::underflow`) and fails.
    /// # Safety
    /// As for `start_scanout`.
    pub async unsafe fn check_scanout(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        crystal_khz: u32,
    ) -> Result<u32, Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        let regs = self.0.io.0;
        self.1
            .check_scanout(&mut self.0, pipe, crystal_khz, || {
                Ok((
                    dccg.retained_timing_clock(regs, clocks, pipe)
                        .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
    /// Read-only: the running timing generator's frame count and position
    /// on `pipe`, the pipe of display `pipe`, read until the frame count is
    /// stable across the position read (as amdgpu_get_vblank_counter_kms).
    pub fn scanout_position(&mut self, pipe: u8) -> Result<ScanoutPosition, Error> {
        let status = self.display_status(pipe).ok_or(Error::Invalid)?;
        let timing = status.pipes[usize::from(pipe)]
            .ok_or(Error::Invalid)?
            .request
            .timing;
        let e = &mut self.0;
        let l = e.layout;
        if pipe >= l.pool.count() {
            return Err(Error::Invalid);
        }
        if e.read(l.otg(pipe, CONTROL))? & 0x10001 != 0x10001 {
            return Err(Error::Busy); // not running
        }
        let blank = e.read(l.otg(pipe, V_BLANK_START_END))?;
        for _ in 0..3 {
            let frame = e.read(l.otg(pipe, FRAME_COUNT))? & FRAME_MASK;
            let position = e.read(l.otg(pipe, STATUS_POSITION))?;
            if e.read(l.otg(pipe, FRAME_COUNT))? & FRAME_MASK == frame {
                return Ok(ScanoutPosition {
                    frame,
                    vpos: position & 0x7fff,
                    hpos: (position >> 16) & 0x7fff,
                    vblank_start: blank & 0x7fff,
                    vblank_end: (blank >> 16) & 0x7fff,
                    timing,
                });
            }
        }
        Err(Error::Busy)
    }
    /// The live scanout as a CPU framebuffer for console adoption.
    pub fn scanout_framebuffer(&self, pipe: u8) -> Result<GenericFb, Error> {
        // Display k scans out on pipe k: read that display's records.
        let status = self.display_status(pipe).ok_or(Error::Invalid)?;
        self.1.scanout_framebuffer(&status, pipe)
    }
    /// Make CPU writes to the live surface visible to display fetch: the
    /// native HDP flush used by staged uploads.
    pub fn flush_scanout_writes(&mut self) -> Result<(), Error> {
        let live = self.0.layout.pool.pipes().any(|d| {
            self.display_status(d)
                .is_some_and(|s| matches!(s.state, State::ScanoutRunning(_)))
        });
        if !live {
            return Err(Error::Busy);
        }
        self.0.flush_surface_writes()
    }
    /// Return a live pipe to black video with fetch drained, routes detached
    /// and clocks gated, ready to start again. Allocations stay retained.
    /// # Safety
    /// As for `start_scanout`; on failure or cancellation the surface must stay
    /// allocated because fetch retirement was not proven.
    pub async unsafe fn stop_scanout(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        crystal_khz: u32,
    ) -> Result<(), Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        let regs = self.0.io.0;
        self.1
            .stop_scanout(&mut self.0, pipe, crystal_khz, || {
                Ok((
                    dccg.retained_timing_clock(regs, clocks, pipe)
                        .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_scanout_tests.rs"]
mod tests;
