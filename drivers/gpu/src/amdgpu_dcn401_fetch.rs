//! Native all-plane disconnect, sharing timing/clock/PM ownership with Otg.
//! Linux: mpc1_remove_mpcc, mpc2_assert_idle_mpcc, hubp2_set_blank_regs,
//! dcn401_disable_plane_sequence and dcn32_hubp_pg_control.
use super::*;

#[path = "amdgpu_dcn401_hubp_power.rs"]
mod power;
pub use power::HubpPower;
#[path = "amdgpu_dcn401_surface.rs"]
mod surface;
#[cfg(feature = "kernel-test")]
pub(super) use surface::post_csc_words;
pub(super) use surface::Surfaces;
pub use surface::{cursor_mode, plane_scale, CursorMode, CursorUnder};
pub use surface::{
    plane_update_type, planes_update_type, Cleared, LivePlanes, PlaneContent, PlanesUpdated,
    UpdateType,
};
pub use surface::{
    Blend, ColorProgram, CursorApplied, DeadlinesApplied, DppApplied, FlipDone, GamutProgram,
    LivePipe, MemoryApplied, MpcApplied, OgamProgram, OverlayScanout, PipeColor, PlaneLayout,
    RequestorApplied, ScanoutPosition, ScanoutRunning, ScanoutUnderflow, SurfaceApplied,
    SurfaceFormat, SurfaceRequest, VblankPhase, CURSOR_MAX, MAX_OVERLAYS,
};
pub use surface::{DccBlock, PlaneSurface, SurfaceBytes, Swizzle, Tiling, YuvColor};
pub use surface::{ExternalSurface, FlipSource};

const HUBP_CONTROL: u64 = 0x5f4;
const HUBP_CLOCK: u64 = 0x5f5;
const MALL: u64 = 0x5f7;
const FLIP: u64 = 0x613;
const FLIP2: u64 = 0x614;
const CURSOR: u64 = 0x679;
const DMDATA: u64 = 0x685;
const LUT3D: u64 = 0x68a;
const GSL: u64 = 0x1b8a;
const TOP: u64 = 0;
const BOTTOM: u64 = 1;
const OPP_ID: u64 = 2;
const UPDATE_LOCK: u64 = 5;
const MPC_STATUS: u64 = 0xe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanesRetired {
    /// HUBPs explicitly blanked and clock-disabled after acknowledged drain.
    pub blanked: u8,
    /// HUBPs already off, proven by native power-gate request and PGFSM state.
    /// Their inaccessible registers were neither read nor written.
    pub powered_off: u8,
}
impl Layout {
    fn hubp(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(self.inst(pipe)) * 0xdc) * 4
    }
    /// DOMAIN0-3_PG_CONFIG/STATUS: the pipe's HUBP/DPP power domain.
    fn pg(self, pipe: u8, status: bool) -> u64 {
        self.base + (0x80 + u64::from(self.inst(pipe)) * 2 + u64::from(status)) * 4
    }
    /// The pipe's MPCC (its DPP's instance, as mpcc_inst = dpp->inst).
    fn mpcc(self, pipe: u8, reg: u64) -> u64 {
        self.mpc_base + (reg + u64::from(self.inst(pipe)) * 0x15) * 4
    }
    /// MPC_OUT_MUX of the pipe's OPP.
    fn out_mux(self, pipe: u8) -> u64 {
        self.mpc_base + (0x2f2 + u64::from(self.inst(pipe)) * 4) * 4
    }
}
impl<I: Io> Engine<I> {
    fn hubp_powered(&mut self, pipe: u8) -> Result<bool, Error> {
        let config = self.read(self.layout.pg(pipe, false))? & 0x101;
        let state = self.read(self.layout.pg(pipe, true))? & 0xc0000000;
        match (config, state) {
            (0 | 1, 0) => Ok(true),
            (0x100, 0x80000000) => Ok(false),
            _ => Err(Error::Busy), // transitional or contradictory power state
        }
    }
    fn auxiliary_fetchers_stopped(&mut self, pipe: u8) -> Result<(), Error> {
        // No abort protocol exists here for in-flight metadata or 3D-LUT loads.
        // Keep their allocations; require these independent sources disabled.
        for (r, mask) in [(DMDATA, 0x0fff0007), (LUT3D, 1), (MALL, 0x10)] {
            if self.read(self.layout.hubp(pipe, r))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    pub(super) fn fetchers_stopped(&mut self) -> Result<(), Error> {
        self.fetchers_stopped_except(None)
    }
    /// As `fetchers_stopped`, except that the one owned live scanout must show
    /// exactly its connected, unblanked fetch of the owned surface.
    pub(in crate::amdgpu_dcn401_otg) fn fetchers_stopped_except(
        &mut self,
        live: Option<ScanoutRunning>,
    ) -> Result<(), Error> {
        let l = self.layout;
        let mine = live.map_or_else(alloc::vec::Vec::new, |s| s.live_pipes(self.status.cursor));
        for pipe in l.pool.pipes() {
            // The owned live scanout's pipes (every plane, both ODM halves),
            // and another display's, must be exactly that.
            let theirs = self.displays.siblings.live[usize::from(pipe)];
            if let Some(lp) = mine.iter().copied().find(|l| l.pipe == pipe).or(theirs) {
                if !self.hubp_powered(pipe)? {
                    return Err(Error::Busy);
                }
                self.live_pipe(lp)?;
                self.auxiliary_fetchers_stopped(pipe)?;
                continue;
            }
            if !self.hubp_powered(pipe)? {
                continue;
            }
            // DCN401 uses hubp2 blanking, which clears TTU_DISABLE. It does
            // not install the older hubp1_disconnect callback. Blank + drain
            // + disabled fetch clock are the required powered-on witnesses.
            for (r, mask, value) in [(HUBP_CONTROL, 7, 3), (HUBP_CLOCK, 1, 0), (CURSOR, 1, 0)] {
                if self.read(l.hubp(pipe, r))? & mask != value {
                    return Err(Error::Busy);
                }
            }
            self.auxiliary_fetchers_stopped(pipe)?;
        }
        Ok(())
    }
    fn planes_preflight(&mut self) -> Result<PlanesRetired, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        let l = self.layout;
        let mut powered_off = 0;
        let kept = self.displays.siblings.pipes;
        for p in l.pool.pipes() {
            // Other displays' planes are theirs: neither checked nor retired.
            if kept & 1 << p != 0 {
                continue;
            }
            // Timing may run to latch the MPC disconnect; external streams
            // must already be stopped. Do not steal an inherited transaction.
            self.preflight(p, true)?;
            if self.read(l.otg(p, GSL))? & 0x8000000f != 0
                || self.read(l.mpcc(p, UPDATE_LOCK))? & 0x70 != 0
            {
                return Err(Error::Busy);
            }
            for at in [
                l.out_mux(p),
                l.mpcc(p, TOP),
                l.mpcc(p, BOTTOM),
                l.mpcc(p, OPP_ID),
                l.mpcc(p, UPDATE_LOCK),
            ] {
                // Each selector names a pipe-block instance (DPP, MPCC or
                // OPP); one past 3 or fused is foreign.
                let select = self.read(at)? & 0xf;
                if select != 0xf && l.pool.pipe(select as u8).is_none() {
                    return Err(Error::Unsupported);
                }
            }
            if !self.hubp_powered(p)? {
                powered_off |= 1 << p;
                continue;
            }
            self.auxiliary_fetchers_stopped(p)?;
            if self.read(l.hubp(p, HUBP_CONTROL))? & 4 != 0
                || self.read(l.hubp(p, FLIP))? & 0x301 != 0
                || self.read(l.hubp(p, FLIP2))? & 0x100 != 0
            {
                return Err(Error::Busy);
            }
        }
        Ok(PlanesRetired {
            blanked: l.pool.all() & !powered_off & !kept,
            powered_off,
        })
    }
    async fn wait_plane_drain(
        &mut self,
        plan: PlanesRetired,
        blank: bool,
        deadline: narf_time::Deadline,
    ) -> Result<(), Error> {
        let l = self.layout;
        let kept = self.displays.siblings.pipes;
        loop {
            let mut blocked = None;
            for p in l.pool.pipes().filter(|p| kept & 1 << p == 0) {
                let at = l.mpcc(p, MPC_STATUS);
                let status = self.read(at)?;
                // Native Linux accepts DISABLED, or waits for IDLE. Also
                // reject contradictory BUSY even when another bit is asserted.
                if status & 2 != 0 || status & 5 == 0 {
                    blocked.get_or_insert(at);
                }
                if self.hubp_powered(p)? != (plan.blanked & (1 << p) != 0) {
                    return Err(Error::Busy);
                }
                if plan.blanked & (1 << p) != 0 {
                    let at = l.hubp(p, HUBP_CONTROL);
                    let value = self.read(at)?;
                    if value & 4 != 0 {
                        return Err(Error::Busy);
                    }
                    if value & 2 == 0 || (blank && value & 0x1001 != 1) {
                        blocked.get_or_insert(at);
                    }
                }
            }
            if let Some(at) = blocked {
                if deadline.expired() {
                    return Err(Error::Timeout(at));
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
            } else {
                return Ok(());
            }
        }
    }
    async fn disconnect_planes(&mut self, plan: PlanesRetired) -> Result<(), Error> {
        let l = self.layout;
        let deadline = narf_time::Deadline::after_us(100_000);
        let kept = self.displays.siblings.pipes;
        let ours: alloc::vec::Vec<u8> = l.pool.pipes().filter(|p| kept & 1 << p == 0).collect();
        // Retire the whole display tree but other displays' pipes, including
        // inherited cross-routes. Disconnect outputs before each MPCC's
        // top/bottom/OPP/update-lock mux.
        for &p in &ours {
            self.update(l.out_mux(p), 0xf, 0xf)?;
        }
        for &p in &ours {
            for r in [TOP, BOTTOM, OPP_ID, UPDATE_LOCK] {
                self.update(l.mpcc(p, r), 0xf, 0xf)?;
            }
        }
        for p in l.pool.pipes() {
            if plan.blanked & (1 << p) != 0 {
                self.update(l.hubp(p, CURSOR), 1, 0)?;
            }
        }
        // Keep clocks running until all MPCCs and HUBPs acknowledge drain.
        self.wait_plane_drain(plan, false, deadline).await?;
        for p in l.pool.pipes() {
            if plan.blanked & (1 << p) != 0 {
                self.update(l.hubp(p, HUBP_CONTROL), 0x1001, 1)?;
                self.update(l.hubp(p, MALL), 0x1f, 8)?;
                self.update(l.hubp(p, FLIP2), 0x100, 0)?;
            }
        }
        self.wait_plane_drain(plan, true, deadline).await?;
        for p in l.pool.pipes() {
            if plan.blanked & (1 << p) != 0 {
                self.update(l.hubp(p, HUBP_CLOCK), 1, 0)?;
            }
        }
        self.wait_plane_drain(plan, true, deadline).await?;
        self.fetchers_stopped()?;
        for &p in &ours {
            for at in [
                l.out_mux(p),
                l.mpcc(p, TOP),
                l.mpcc(p, BOTTOM),
                l.mpcc(p, OPP_ID),
                l.mpcc(p, UPDATE_LOCK),
            ] {
                if self.read(at)? & 0xf != 0xf {
                    return Err(Error::Readback(at));
                }
            }
            if self.read(l.mpcc(p, UPDATE_LOCK))? & 0x70 != 0
                || self.read(l.otg(p, LOCK))? & 0x101 != 0
                || self.read(l.otg(p, GSL))? & 0x8000000f != 0
            {
                return Err(Error::Busy);
            }
        }
        // A fused OTG's witnesses are (0, 0): never read.
        for (at, mask) in l.idle.into_iter().filter(|&(_, mask)| mask != 0) {
            let timing = l
                .pool
                .pipes()
                .any(|p| at == l.otg(p, CONTROL) || at == l.otg(p, CLOCK));
            if !timing && !self.sibling_register(at) && self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    /// With every plane retired the overlays' staging ends: a plane's
    /// records on a pipe with neither timing nor blank of its own, other
    /// than the display's, are an overlay's (ODM pipes have none). Their
    /// pipes and DETs return to the pool; the next configuration stages its
    /// own overlays.
    pub(in crate::amdgpu_dcn401_otg) fn drop_overlays(&mut self) {
        let own = usize::from(self.displays.selected);
        let pipes = self.layout.pool.pipes();
        let s = &mut self.status;
        let overlay =
            |s: &Status, i: usize| i != own && s.pipes[i].is_none() && s.blanks[i].is_none();
        for i in pipes.map(usize::from) {
            if !overlay(s, i) {
                continue;
            }
            s.surfaces[i] = None;
            s.memory[i] = None;
            s.dpps[i] = None;
            s.mpcs[i] = None;
        }
        if let Some(r) = s.requestor.as_mut() {
            if r.overlays.iter().any(Option::is_some) {
                r.overlays = [None; MAX_OVERLAYS];
                s.deadlines = None;
            }
        }
    }
    pub(super) async fn retire_planes(&mut self) -> Result<PlanesRetired, Error> {
        let plan = self.planes_preflight()?;
        self.status.state = State::RetiringPlanes;
        match self.disconnect_planes(plan).await {
            Ok(()) => {
                self.status.planes_retired = Some(plan);
                self.drop_overlays();
                self.status.state = State::PlanesRetired;
                Ok(plan)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Disconnect every pipe's MPC output/MPCC and drain powered HUBPs
    /// before blanking and stopping their fetch clocks. Timing can keep running
    /// for disconnect latching; every external stream must already be stopped.
    /// Leaves DPP clocks, power domains, timing and all allocations retained.
    /// # Safety
    /// Stop CPU scanout writers; exclude firmware/FAMS and all concurrent
    /// surface/cursor/metadata/LUT, MPC, power and timing writers. Retain every
    /// associated allocation and translation, including inherited resources.
    /// This does not retire GPUVM, writeback or other engines and never grants
    /// permission to free/reuse memory. Retain this owner after cancellation.
    pub async unsafe fn retire_planes(&mut self) -> Result<PlanesRetired, Error> {
        self.0.retire_planes().await
    }
}
