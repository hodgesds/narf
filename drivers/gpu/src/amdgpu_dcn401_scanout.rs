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
const MPC_STATUS: u64 = 0xe;
const MPCC_CONTROL: u64 = 3;
const MPCC_MODE_TOP_ONLY: u32 = 2;
const DRAM_STATE: u64 = 0x4fc;
const PSTATE_FORCE: u32 = 0x30; // ALLOW_PSTATE_CHANGE_FORCE_{VALUE,ENABLE}
const PSTATE_DISALLOWED: u32 = 0x20;

/// Evidence that one owned surface is the pipe's live scanout source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanoutRunning {
    pub pipe: u8,
    pub stream: u8,
    /// The admitted plan whose deadlines this fetch runs under.
    pub plan: dml::Plan,
    /// GPU address the HUBP reported in use after the configuration latched.
    pub address: u64,
    /// Two distinct frame counts sampled after the latch with no underflow.
    pub frame_before: u32,
    pub frame_after: u32,
}

/// What an activation or stop works on, gathered from the retained reports.
#[derive(Clone, Copy, Debug)]
pub(super) struct Pipe {
    pub(super) pipe: u8,
    pub(super) address: u64,
    pub(super) black: u32,
    pub(super) timeout_us: u64,
    /// Fail waits on underflow; cleared only while recovering from one.
    pub(super) watch: bool,
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
    fn dpp_control(&self, pipe: u8) -> u64 {
        self.layout.base + (DPP_CONTROL + u64::from(pipe) * 0x16b) * 4
    }
    fn optc_input(&self, pipe: u8) -> u64 {
        self.layout.base + (OPTC_INPUT + u64::from(pipe) * 0x10) * 4
    }
    /// The only MPCC/DPP/OPP/OTG instance used for a pipe is the pipe itself.
    fn routes(&self, pipe: u8, connected: bool) -> [(u64, u32); 5] {
        let l = self.layout;
        let p = u32::from(pipe);
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
        for (at, mask) in [
            (self.layout.hubp(pipe, HUBP_CONTROL), HUBP_UNDERFLOW),
            (self.optc_input(pipe), OPTC_UNDERFLOW),
        ] {
            if self.read(at)? & mask != 0 {
                return Err(Error::Underflow(at));
            }
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
            (l.opp(pipe, DPG_PENDING), 1, 0),
            (l.mpcc(pipe, UPDATE_LOCK), 0x70, 0),
            (l.otg(pipe, GSL), 0x8000_000f, 0),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Busy);
            }
        }
        self.underflow(pipe)
    }
    /// Fetch stopped exactly as staged: blank and drained HUBP with its clock
    /// gated, DPP clock gated, all routes detached and the DPG showing black.
    fn staged(&mut self, p: Pipe) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask, value) in [
            (
                l.hubp(p.pipe, HUBP_CONTROL),
                BLANK_EN | NO_OUTSTANDING | TTU_DISABLE,
                3,
            ),
            (l.hubp(p.pipe, HUBP_CLOCK), 1, 0),
            (self.dpp_control(p.pipe), DPP_CLOCK_ENABLE, 0),
            (l.opp(p.pipe, DPG), DPG_FIELDS, p.black),
            (l.mpcc(p.pipe, MPCC_CONTROL), 3, MPCC_MODE_TOP_ONLY),
            (l.hubp(p.pipe, CURSOR), CURSOR_REQ_MODE | 1, CURSOR_REQ_MODE),
            (l.hubp(p.pipe, ADDRESS), u32::MAX, p.address as u32),
            (
                l.hubp(p.pipe, ADDRESS_HIGH),
                0xffff,
                (p.address >> 32) as u32,
            ),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        for (at, value) in self.routes(p.pipe, false) {
            if self.read(at)? & 0xf != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    async fn lock(&mut self, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        self.update(
            l.otg(pipe, GLOBAL_CONTROL2),
            LOCK_SELECT,
            u32::from(pipe) << 25,
        )?;
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, LOCK_REQUEST)?;
        // Linux waits only 10 us and proceeds; here the lock must be held.
        self.wait(l.otg(pipe, LOCK), LOCK_STATUS, LOCK_STATUS, 1000)
            .await
    }
    async fn latched(
        &mut self,
        p: Pipe,
        mut done: impl FnMut(&mut Self) -> Result<Option<u64>, Error>,
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_us(p.timeout_us);
        loop {
            if p.watch {
                self.underflow(p.pipe)?;
            }
            match done(self)? {
                None => return Ok(()),
                Some(at) if deadline.expired() => return Err(Error::Timeout(at)),
                Some(_) => {}
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(10).as_instant()).await;
        }
    }
    async fn fresh_frames(&mut self, p: Pipe) -> Result<(u32, u32), Error> {
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
            (l.hubp(pipe, FLIP), FLIP_PENDING),
            (l.mpcc(pipe, UPDATE_LOCK), 0x70),
        ] {
            if self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        self.underflow(pipe)
    }
    /// Re-address the live fetch under the master-update lock (a VSYNC flip:
    /// the staged flip type is 0) and wait for the HUBP to report the new
    /// surface in use, without underflow. Returns the frame count then.
    pub(super) async fn flip_to(&mut self, p: Pipe) -> Result<u32, Error> {
        let l = self.layout;
        let pipe = p.pipe;
        self.lock(pipe).await?;
        self.update(l.hubp(pipe, ADDRESS_HIGH), 0xffff, (p.address >> 32) as u32)?;
        self.update(l.hubp(pipe, ADDRESS), u32::MAX, p.address as u32)?;
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, 0)?;
        self.latched(p, |e| e.in_use(pipe, p.address)).await?;
        Ok(self.read(l.otg(pipe, FRAME_COUNT))? & FRAME_MASK)
    }
    /// Connect and unblank under one OTG master-update lock so DPG release,
    /// MPCC insertion, address and HUBP unblank latch at the same VUPDATE.
    pub(super) async fn start_fetch(&mut self, p: Pipe) -> Result<(u32, u32), Error> {
        let l = self.layout;
        let pipe = p.pipe;
        let hubbub = |r: u64| l.base + r * 4;
        // Clocks first, while blanked and detached; Linux never has them gated
        // on a live plane.
        self.update(l.hubp(pipe, HUBP_CLOCK), 1, 1)?;
        self.update(self.dpp_control(pipe), DPP_CLOCK_ENABLE, DPP_CLOCK_ENABLE)?;
        self.wait(l.hubp(pipe, HUBP_CONTROL), 0x1007, 3, 100_000)
            .await?;
        self.lock(pipe).await?;
        // dcn401_program_front_end_for_ctx forces P-state off across 0->1.
        self.update(hubbub(DRAM_STATE), PSTATE_FORCE, PSTATE_DISALLOWED)?;
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(500).as_instant()).await;
        self.update(l.opp(pipe, DPG), DPG_FIELDS, 0)?; // video mode
        for (at, value) in [
            (l.mpcc(pipe, BOTTOM), 0xf),
            (l.mpcc(pipe, TOP), u32::from(pipe)),
            (l.mpcc(pipe, OPP_ID), u32::from(pipe)),
            (l.mpcc(pipe, UPDATE_LOCK), u32::from(pipe)),
            (l.out_mux(pipe), u32::from(pipe)),
        ] {
            self.update(at, 0xf, value)?;
        }
        // Re-arm the flip: high half first, the low write publishes it.
        self.update(l.hubp(pipe, ADDRESS_HIGH), 0xffff, (p.address >> 32) as u32)?;
        self.update(l.hubp(pipe, ADDRESS), u32::MAX, p.address as u32)?;
        self.update(l.hubp(pipe, HUBP_CONTROL), BLANK_EN | TTU_DISABLE, 0)?;
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, 0)?;
        // dcn401_post_unlock_program_front_end: the new surface is in use only
        // when no flip is pending and EARLIEST_INUSE reports its address. A
        // requested-address readback is not that evidence.
        self.latched(p, |e| {
            if let Some(at) = e.in_use(pipe, p.address)? {
                return Ok(Some(at));
            }
            for (at, mask, value) in [
                (l.opp(pipe, DPG_PENDING), 1, 0),
                (l.opp(pipe, DPG), DPG_EN, 0),
                (l.otg(pipe, DOUBLE_BUFFER), OTG_UPDATE_PENDING, 0),
                (l.otg(pipe, PIPE_UPDATE), PIPE_PENDING, 0),
                (l.mpcc(pipe, MPC_STATUS), 4, 0), // MPCC no longer DISABLED
            ] {
                if e.read(at)? & mask != value {
                    return Ok(Some(at));
                }
            }
            Ok(None)
        })
        .await?;
        self.update(hubbub(DRAM_STATE), PSTATE_FORCE, 0)?;
        for (at, value) in self.routes(pipe, true) {
            if self.read(at)? & 0xf != value {
                return Err(Error::Readback(at));
            }
        }
        if self.read(l.hubp(pipe, HUBP_CONTROL))? & (BLANK_EN | TTU_DISABLE) != 0 {
            return Err(Error::Readback(l.hubp(pipe, HUBP_CONTROL)));
        }
        self.fresh_frames(p).await
    }
    /// Black first, detach under the lock, then drain and blank the HUBP and
    /// gate its clocks only after the MPCC and memory requests are idle.
    pub(super) async fn stop_fetch(&mut self, p: Pipe) -> Result<(), Error> {
        let l = self.layout;
        let pipe = p.pipe;
        // The cursor is a fetch source too; it latches off with the black.
        self.hide_cursor(pipe)?;
        self.lock(pipe).await?;
        self.update(l.opp(pipe, DPG), DPG_FIELDS, p.black)?;
        for (at, value) in self.routes(pipe, false) {
            self.update(at, 0xf, value)?;
        }
        self.update(l.otg(pipe, LOCK), LOCK_REQUEST, 0)?;
        // Black must be on screen before the MPCC may report disconnection.
        self.latched(p, |e| {
            for (at, mask, value) in [
                (l.opp(pipe, DPG_PENDING), 1, 0),
                (l.opp(pipe, DPG), DPG_FIELDS, p.black),
                (l.otg(pipe, DOUBLE_BUFFER), OTG_UPDATE_PENDING, 0),
            ] {
                if e.read(at)? & mask != value {
                    return Ok(Some(at));
                }
            }
            // mpc2_assert_idle_mpcc: DISABLED, or IDLE and not BUSY.
            let at = l.mpcc(pipe, MPC_STATUS);
            let status = e.read(at)?;
            Ok((status & 2 != 0 || status & 5 == 0).then_some(at))
        })
        .await?;
        // hubp2_set_blank(true): no outstanding requests before blanking.
        self.wait(
            l.hubp(pipe, HUBP_CONTROL),
            NO_OUTSTANDING,
            NO_OUTSTANDING,
            100_000,
        )
        .await?;
        self.update(l.hubp(pipe, HUBP_CONTROL), BLANK_EN | TTU_DISABLE, BLANK_EN)?;
        self.wait(l.hubp(pipe, HUBP_CONTROL), 0x1007, 3, 100_000)
            .await?;
        self.update(l.hubp(pipe, HUBP_CLOCK), 1, 0)?;
        self.update(self.dpp_control(pipe), DPP_CLOCK_ENABLE, 0)?;
        self.staged(p)
    }
    /// The owned pipe as `start_fetch` left it: unblanked fetch of the owned
    /// surface, clocks on, routes connected, DPG released, cursor off.
    pub(in crate::amdgpu_dcn401_otg) fn live_fetch(
        &mut self,
        pipe: u8,
        address: u64,
    ) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask, value) in [
            (l.hubp(pipe, HUBP_CONTROL), BLANK_EN | 4 | TTU_DISABLE, 0),
            (l.hubp(pipe, HUBP_CLOCK), 1, 1),
            (self.dpp_control(pipe), DPP_CLOCK_ENABLE, DPP_CLOCK_ENABLE),
            (l.opp(pipe, DPG), DPG_FIELDS, 0),
            (l.mpcc(pipe, MPC_STATUS), 4, 0),
            (
                l.hubp(pipe, CURSOR),
                1,
                u32::from(
                    self.status
                        .cursor
                        .is_some_and(|c| c.pipe == pipe && c.visible),
                ),
            ),
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
        for (at, value) in self.routes(pipe, true) {
            if self.read(at)? & 0xf != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// Record an underflow, return the pipe to black through the normal stop
    /// sequence without failing on the (sticky) status, then clear it. Linux
    /// hubp2_clear_underflow/optc1_clear_optc_underflow are single strobes.
    pub(super) async fn recover_fetch(&mut self, p: Pipe) -> Result<ScanoutUnderflow, Error> {
        let l = self.layout;
        let hubp = self.read(l.hubp(p.pipe, HUBP_CONTROL))?;
        let optc = self.read(self.optc_input(p.pipe))?;
        let report = ScanoutUnderflow {
            pipe: p.pipe,
            address: p.address,
            hubp_status: ((hubp & HUBP_UNDERFLOW) >> 28) as u8,
            optc: optc & OPTC_UNDERFLOW != 0,
            frame: self.read(l.otg(p.pipe, FRAME_COUNT))? & FRAME_MASK,
        };
        self.stop_fetch(Pipe { watch: false, ..p }).await?;
        for (at, clear) in [
            (l.hubp(p.pipe, HUBP_CONTROL), HUBP_UNDERFLOW_CLEAR),
            (self.optc_input(p.pipe), OPTC_UNDERFLOW_CLEAR),
        ] {
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
        (clock, config): (dccg::Applied, DisplayContext),
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
        e.verify_requestor(d.pipe)?;
        e.deadline_writes(d.pipe, &d.plan, true)?;
        let refclk = e.dchub_refclk_khz(crystal_khz)?;
        if !deadline::bound(&d.plan, blank.timing.request, a, clock, refclk) {
            return Err(Error::Invalid);
        }
        Ok(Pipe {
            pipe: d.pipe,
            address: surface.address,
            black: 0x41 | blank.request.depth.dpg() << 12,
            timeout_us: blank.timeout_us()?,
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
                    stream,
                    plan: d.plan,
                    address: p.address,
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
        if p.address != running.address || deadlines.plan != running.plan {
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
        if p.address != running.address {
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
            // No video record at all is a missing predecessor, not contention.
            _ if s.dp_video_running.is_none() && s.hdmi_video_running.is_none() => {
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
        } else {
            State::DpVideoRunning(stream)
        }
    }
    fn video_verify_scanout(&mut self, live: ScanoutRunning) -> Result<(), Error> {
        if self.status.hdmi_video_running.is_some() {
            self.hdmi_video_verify_scanout(live)
        } else {
            self.dp_video_verify_scanout(live)
        }
    }
}
impl Surfaces {
    /// CPU view of the live scanout: bus-physical BAR address of the owned
    /// surface, its visible size and byte pitch, for console adoption.
    pub(in crate::amdgpu_dcn401_otg) fn scanout_framebuffer<I: Io>(
        &self,
        e: &Engine<I>,
        pipe: u8,
    ) -> Result<GenericFb, Error> {
        let running = e.status.scanout.ok_or(Error::Invalid)?;
        if e.status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
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
    /// The live scanout as a CPU framebuffer for console adoption.
    pub fn scanout_framebuffer(&self, pipe: u8) -> Result<GenericFb, Error> {
        self.1.scanout_framebuffer(&self.0, pipe)
    }
    /// Make CPU writes to the live surface visible to display fetch: the
    /// native HDP flush used by staged uploads.
    pub fn flush_scanout_writes(&mut self) -> Result<(), Error> {
        if !matches!(self.0.status.state, State::ScanoutRunning(_)) {
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
