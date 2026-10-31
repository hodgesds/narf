//! Phantom lifecycle. It aliases the retained main surface; no allocation or
//! client fence may retire until firmware is disabled and this pipe drains.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubvpApplied {
    pub main: u8,
    pub phantom: u8,
    pub active: bool,
}
impl<I: Io> Engine<I> {
    pub(in crate::amdgpu_dcn401_otg) fn subvp(&self) -> Option<SubvpApplied> {
        self.status.subvp.or_else(|| {
            self.displays
                .parked
                .iter()
                .enumerate()
                .filter(|(slot, _)| *slot != usize::from(self.displays.selected))
                .find_map(|(_, status)| status.subvp)
        })
    }
    pub(in crate::amdgpu_dcn401_otg) fn reserve_subvp(&mut self, main: u8) -> Result<u8, Error> {
        if self.status.state != State::ScanoutRunning(main)
            || self.status.subvp.is_some()
            || self.status.drr.is_some()
            || self.status.cursor.is_some_and(|c| c.visible)
            || self.displays.siblings.pipes != 0
        {
            return Err(Error::Busy);
        }
        let a = self.status.scanout.ok_or(Error::Busy)?;
        let surface = self.status.surfaces[usize::from(main)].ok_or(Error::Busy)?;
        let layout = surface.request.layout();
        if a.plan.mode.planes[1..].iter().any(Option::is_some)
            || surface.request.pipe_mask() != bit(main)
            || layout.rotation != spl::Rotation::R0
            || layout.src.x != 0
            || layout.src.y != 0
            || layout.dst.x != 0
            || layout.dst.y != 0
            || surface.request.surface.tiling != Tiling::LINEAR
            || surface.request.format.is_video()
            || self
                .status
                .requestor
                .is_none_or(|r| r.overlays.iter().any(Option::is_some))
        {
            return Err(Error::Unsupported);
        }
        let held = Siblings::of(&self.status).pipes;
        let q = self
            .layout
            .pool
            .pipes()
            .find(|&p| held & bit(p) == 0)
            .ok_or(Error::Busy)?;
        let l = self.layout;
        for (at, mask, want) in [
            (l.otg(q, CONTROL), 0x10001, 0),
            (l.otg(q, LOCK), 0x101, 0),
            (l.out_mux(q), 0xf, 0xf),
            (l.mpcc(q, TOP), 0xf, 0xf),
        ] {
            if self.read(at)? & mask != want {
                return Err(Error::Busy);
            }
        }
        let mpc = self.read(l.mpcc(q, MPC_STATUS))?;
        if mpc & 2 != 0 || mpc & 5 == 0 {
            return Err(Error::Busy);
        }
        for (at, value) in self.routes(q, false) {
            if self.read(at)? & 0xf != value {
                return Err(Error::Busy);
            }
        }
        if self.hubp_powered(q)? {
            self.hubp_transactions_stopped(q, false)?;
            self.dpp_stopped(q, false)?;
        }
        self.status.subvp = Some(SubvpApplied {
            main,
            phantom: q,
            active: false,
        });
        self.status.state = State::UpdatingStream(main);
        Ok(q)
    }
    pub(in crate::amdgpu_dcn401_otg) async fn program_subvp(
        &mut self,
        plan: &dml::Plan,
        clock: dccg::Applied,
    ) -> Result<(), Error> {
        let vp = self.status.subvp.ok_or(Error::Busy)?;
        let (main, q) = (vp.main, vp.phantom);
        if self.status.state != State::UpdatingStream(main)
            || vp.active
            || clock.request.pipe != q
            || !plan.readmits()
            || plan.det_bytes != 0
            || self.status.scanout.is_none_or(|s| {
                Some(s.plan.mode) != plan.subvp_main_mode() || s.plan.soc != plan.soc
            })
            || !plan
                .pstate
                .is_some_and(|p| p.subvp.is_some_and(|s| s.phantom))
        {
            return Err(Error::Busy);
        }
        let l = self.layout;
        let mut timing = self.status.pipes[usize::from(main)].ok_or(Error::Busy)?;
        timing.request.pipe = q;
        timing.request.timing = plan.mode.timing;
        timing.request.sync = plan.sync;
        timing.request.signal = Signal::DisplayPort;
        timing.clock = clock;
        timing.request.validate_clock(clock)?;
        let mut surface = self.status.surfaces[usize::from(main)].ok_or(Error::Busy)?;
        let mut layout = surface.request.layout();
        layout.src.height = plan.mode.timing.v_active as i32;
        layout.dst.height = plan.mode.timing.v_active as i32;
        layout.stream_height = plan.mode.timing.v_active;
        surface.request.pipe = q;
        surface.request.plane = Some(layout);
        let main_dpp = self.status.dpps[usize::from(main)].ok_or(Error::Busy)?;
        let mut dpp = DppApplied {
            surface,
            timing,
            ..main_dpp
        };
        let mpc = MpcApplied {
            dpp,
            ..self.status.mpcs[usize::from(main)].ok_or(Error::Busy)?
        };
        // Publish aliases before the first await. Cancellation retains the main
        // source and phantom reservation, with ordinary display writes closed.
        self.status.pipes[usize::from(q)] = Some(timing);
        self.status.surfaces[usize::from(q)] = Some(surface);
        self.gate_hubp(HubpPower {
            pipe: q,
            powered: true,
        })
        .await?;
        self.dpp_stopped(q, false)?;
        self.program_det_segments(q, 0)?;
        self.wait(
            l.base + (0x4bb + u64::from(l.inst(q))) * 4,
            0x1f00,
            0,
            100_000,
        )
        .await?;
        self.program(timing.request.plan()?).await?;
        self.global_sync_writes(timing.request.plan()?, false)?;
        self.update(l.hubp(q, HUBP_CLOCK), 1, 1)?;
        for (r, mask) in [(0x62c, 0x3fffffff), (0x62d, 0x3fffffff), (0x63a, 0x79)] {
            let value = self.read(l.hubp(main, r))? & mask;
            self.update(l.hubp(q, r), mask, value)?;
        }
        for (_, scaler) in surface.request.scalers() {
            for (r, mask, value) in surface.registers(&scaler) {
                self.update(l.hubp(q, r), mask, value)?;
            }
        }
        self.update(l.dpp(q, 0xcc5), 0x10, 0x10)?;
        dpp.coef_ram = self.program_dpp_live(&mut dpp).await?;
        for (at, mask, value) in l.mpc_rgb(&mpc) {
            self.update(at, mask, value)?;
        }
        for (r, mask, value) in requestor::requestor(l.inst(q)) {
            self.update(l.hubp(q, r), mask, value)?;
        }
        self.deadline_writes(q, plan, false)?;
        let mut blank = self.status.blanks[usize::from(main)].ok_or(Error::Busy)?;
        blank.request.pipe = q;
        blank.timing = timing;
        self.update(l.opp(q, 0x188c), 0x13, 3)?;
        for (r, mask, value) in blank.request.segment_registers(timing.request.plan()?, 0) {
            self.update(l.opp(q, r), mask, value)?;
        }
        for (at, value) in self.routes(q, true) {
            self.update(at, 0xf, value)?;
        }
        self.update(l.vtg(q), 0x80000000, 0x80000000)?;
        self.update(l.otg(q, CONTROL), 0x301, 0x201)?;
        self.wait(l.otg(q, CONTROL), 0x10001, 0x10001, blank.timeout_us()?)
            .await?;
        // The main is already scanning out, so enable_blank's whole-board
        // stopped-fetch check cannot apply. Observe a fresh phantom frame
        // using the shared scheduler wait before its post-enable disable.
        let frame = self.read(l.otg(q, 0x1b4d))?;
        self.wait(l.otg(q, 0x1b4d), 1, (frame ^ 1) & 1, blank.timeout_us()?)
            .await?;
        self.update(l.opp(q, 0x1854), 0x01ff3171, 0)?;
        self.update(l.hubp(q, HUBP_CONTROL), 0x1001, 0)?;
        // hubp32_phantom_hubp_post_enable / optc401_phantom_crtc_post_enable:
        // leave a programmed, connected but blank phantom for DMUB to drive.
        self.update(l.hubp(q, FLIP2), 0x100, 0)?;
        self.update(l.hubp(q, HUBP_CONTROL), 0x1001, 1)?;
        self.wait(l.hubp(q, HUBP_CONTROL), 2, 2, 100_000).await?;
        self.update(l.otg(q, CONTROL), 0x301, 0)?;
        self.wait(l.otg(q, CONTROL), 0x10001, 0, 150_000).await?;
        self.update(l.hubp(q, MALL), 7, 1)?;
        self.update(l.hubp(main, MALL), 7, 2)?;
        self.update(l.hubp(main, 0x5f6), 0x80, 0x80)?;
        self.update(l.hubp(main, CURSOR), 4, 4)?;
        self.underflow(main)?;
        self.status.state = State::ScanoutRunning(main);
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) fn handoff_subvp(
        &mut self,
        enable: bool,
    ) -> Result<(), Error> {
        let Some(vp) = self.subvp() else {
            return Ok(());
        };
        self.select_display(vp.main)?;
        if self.status.state != State::ScanoutRunning(vp.main) {
            return Err(Error::Busy);
        }
        if !enable {
            let total = self.status.pipes[usize::from(vp.main)]
                .ok_or(Error::Busy)?
                .request
                .timing
                .v_total;
            for (reg, mask, value) in [
                (V_MIN, 0x7fff, total - 1),
                (0x1b31, 0x7fff, total - 1),
                (0x1b32, 0x7fff, 0),
                (V_CONTROL, drr::DRR_FIELDS, 0),
            ] {
                self.update(self.layout.otg(vp.main, reg), mask, value)?;
            }
        }
        self.status.subvp.as_mut().ok_or(Error::Busy)?.active = enable;
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) async fn retire_subvp(&mut self) -> Result<Option<u8>, Error> {
        let Some(vp) = self.subvp() else {
            return Ok(None);
        };
        self.select_display(vp.main)?;
        if vp.active || self.status.state != State::ScanoutRunning(vp.main) {
            return Err(Error::Busy);
        }
        let (p, q) = (vp.main, vp.phantom);
        self.status.state = State::UpdatingStream(p);
        let l = self.layout;
        // Let double-buffered disconnect/DET writes latch before disabling the
        // phantom OTG. The matching FAMS2 config-off was already acknowledged.
        self.update(l.vtg(q), 0x80000000, 0x80000000)?;
        self.update(l.otg(q, CONTROL), 0x301, 0x201)?;
        self.wait(l.otg(q, CONTROL), 0x10001, 0x10001, 150_000)
            .await?;
        self.update(l.hubp(q, HUBP_CONTROL), 0x1001, 1)?;
        self.wait(l.hubp(q, HUBP_CONTROL), 2, 2, 100_000).await?;
        for (at, value) in self.routes(q, false) {
            self.update(at, 0xf, value)?;
        }
        let frame = self.read(l.otg(q, 0x1b4d))?;
        self.wait(l.otg(q, 0x1b4d), 1, (frame ^ 1) & 1, 150_000)
            .await?;
        self.wait(l.mpcc(q, MPC_STATUS), 2, 0, 100_000).await?;
        if self.read(l.mpcc(q, MPC_STATUS))? & 5 == 0 {
            return Err(Error::Busy);
        }
        self.disable(q).await?;
        self.update(l.hubp(q, MALL), 0x1f, 8)?;
        self.update(l.hubp(q, HUBP_CLOCK), 1, 0)?;
        self.update(l.dpp(q, 0xcc5), 0x10, 0)?;
        self.update(l.hubp(p, MALL), 0x1f, 8)?;
        self.update(l.hubp(p, 0x5f6), 0x80, 0)?;
        self.status.pipes[usize::from(q)] = None;
        self.status.surfaces[usize::from(q)] = None;
        self.status.subvp = None;
        self.status.state = State::ScanoutRunning(p);
        Ok(Some(q))
    }
}
impl Otg {
    pub(crate) fn subvp(&self) -> Option<SubvpApplied> {
        self.0.subvp()
    }
    pub(crate) fn reserve_subvp(&mut self, main: u8) -> Result<u8, Error> {
        self.0.select_display(main)?;
        self.0.reserve_subvp(main)
    }
    pub(crate) async fn program_subvp(
        &mut self,
        plan: &dml::Plan,
        clock: dccg::Applied,
    ) -> Result<(), Error> {
        self.0.program_subvp(plan, clock).await
    }
    pub(crate) async fn retire_subvp(&mut self) -> Result<Option<u8>, Error> {
        self.0.retire_subvp().await
    }
    pub(crate) fn firmware_subvp(&mut self, enable: bool) -> Result<(), Error> {
        self.0.handoff_subvp(enable)
    }
}
