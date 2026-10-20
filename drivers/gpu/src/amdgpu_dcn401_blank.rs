//! Start internal black timing only, using native optc401_enable_crtc order.
//! No fetcher, MPC tree or link is enabled by this operation.
use super::*;

const FRAME_COUNT: u64 = 0x1b4d;
const FRAME_MASK: u32 = 0xffffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlankRunning {
    pub blank: BlankApplied,
    /// Two distinct 24-bit counters sampled after blank completion. Wrap is
    /// allowed. These are historical evidence, not a live vblank subscription.
    pub frame_before: u32,
    pub frame_after: u32,
}
impl BlankApplied {
    pub(in crate::amdgpu_dcn401_otg) fn timeout_us(self) -> Result<u64, Error> {
        let t = self.timing.request.timing;
        if t.pixel_clock_khz == 0 {
            return Err(Error::Invalid);
        }
        let frame_us = (u64::from(t.h_total) * u64::from(t.v_total) * 1000)
            .div_ceil(u64::from(t.pixel_clock_khz));
        let timeout_us = frame_us * 3 + 5000;
        if timeout_us > 1_000_000 {
            return Err(Error::Invalid);
        }
        Ok(timeout_us)
    }
}
impl<I: Io> Engine<I> {
    fn expect(&mut self, at: u64, mask: u32, value: u32) -> Result<(), Error> {
        if self.read(at)? & mask != value {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) fn verify_blank(
        &mut self,
        blank: BlankApplied,
        plan: Plan,
        running: bool,
    ) -> Result<(), Error> {
        self.verify_blank_route(blank, plan, running, true)
    }
    pub(in crate::amdgpu_dcn401_otg) fn verify_blank_route(
        &mut self,
        blank: BlankApplied,
        plan: Plan,
        running: bool,
        connected: bool,
    ) -> Result<(), Error> {
        self.verify_blank_source(blank, plan, running, connected, false)
    }
    /// `video`: the owned scanout has released the DPG into video mode; every
    /// other OPP/FMT field must still hold its staged value.
    pub(in crate::amdgpu_dcn401_otg) fn verify_blank_source(
        &mut self,
        blank: BlankApplied,
        plan: Plan,
        running: bool,
        connected: bool,
        video: bool,
    ) -> Result<(), Error> {
        let l = self.layout;
        let p = blank.request.pipe;
        // A staged HDMI FRL timing compresses only once its video started it.
        let dsc = plan
            .request
            .dsc
            .filter(|_| plan.request.signal != Signal::HdmiFrl || self.status.frl_dsc == Some(p));
        for (r, mask, value) in plan.registers() {
            self.expect(l.otg(p, r), mask, value)?;
        }
        for (at, mask, value) in [
            (l.otg(p, H_TIMING), 0x103, plan.h_divider()),
            (l.otg(p, V_CONTROL), 0xffff0013, 0),
            (l.otg(p, CLOCK), 0x113, 0x103),
            (l.odm(p, INPUT_CLOCK), 7, 7),
            (l.odm(p, SOURCE), 0xffff0003, plan.source(connected)),
            (l.odm(p, MEMORY), 0xffff, plan.memory()),
            (
                l.odm(p, FORMAT),
                0x33,
                if plan.request.ycbcr420 { 2 } else { 0 } | if dsc.is_some() { 0x10 } else { 0 },
            ),
            (l.vtg(p), 0xffff7fff, plan.vtg | u32::from(running) << 31),
        ] {
            self.expect(at, mask, value)?;
        }
        if plan.request.odm.is_some() {
            self.expect(l.odm(p, WIDTH), 0x1fff, plan.segment_width())?;
        }
        for (segment, o) in plan.opps().enumerate() {
            self.expect(l.opp(o, PIPE), 0x13, 3)?;
            for (r, mask, value) in blank.request.segment_registers(plan, segment as u32) {
                let value = if video && r == DPG { 0 } else { value };
                self.expect(l.opp(o, r), mask, value)?;
            }
        }
        if let Some(cfg) = dsc {
            self.dsc_running(&plan.request, &cfg)?;
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) async fn enable_blank(
        &mut self,
        blank: BlankApplied,
        timeout_us: u64,
    ) -> Result<BlankRunning, Error> {
        let l = self.layout;
        let p = blank.request.pipe;
        // Native DCN401 workaround requires VTG before master enable.
        let plan = blank.timing.request.plan()?;
        self.update(l.odm(p, SOURCE), 0xffff0003, plan.source(true))?;
        if plan.request.odm.is_some() {
            self.update(l.odm(p, MEMORY), 0xffff, plan.memory())?;
        }
        self.update(l.vtg(p), 0x80000000, 0x80000000)?;
        self.update(l.otg(p, CONTROL), 0x301, 0x201)?;
        self.wait_blank_frames(blank, timeout_us).await
    }
    pub(in crate::amdgpu_dcn401_otg) async fn wait_blank_frames(
        &mut self,
        blank: BlankApplied,
        timeout_us: u64,
    ) -> Result<BlankRunning, Error> {
        let l = self.layout;
        let p = blank.request.pipe;
        let deadline = narf_time::Deadline::after_us(timeout_us);
        let mut before = None;
        loop {
            // Recheck each witness together. A cleared pending bit without a
            // current master or a fresh subsequent frame cannot prove blanking.
            let mut blocked = if self.read(l.otg(p, CONTROL))? & 0x10001 != 0x10001 {
                Some(l.otg(p, CONTROL))
            } else {
                None
            };
            for o in blank.timing.request.plan()?.opps() {
                if blocked.is_some() {
                    break;
                }
                if self.read(l.opp(o, PENDING))? & 1 != 0 {
                    blocked = Some(l.opp(o, PENDING));
                } else if self.read(l.opp(o, FMT))? & 0x1000000 != 0 {
                    blocked = Some(l.opp(o, FMT));
                }
            }
            if blocked.is_some() {
                before = None;
            } else {
                let frame = self.read(l.otg(p, FRAME_COUNT))? & FRAME_MASK;
                if let Some(first) = before {
                    if frame != first {
                        self.fetchers_stopped()?;
                        self.verify_blank(blank, blank.timing.request.plan()?, true)?;
                        self.expect(l.otg(p, CONTROL), 0x10301, 0x10201)?;
                        return Ok(BlankRunning {
                            blank,
                            frame_before: first,
                            frame_after: frame,
                        });
                    }
                } else {
                    before = Some(frame);
                }
            }
            #[cfg(feature = "kernel-test")]
            if self.io.pause_wait() {
                core::future::pending::<()>().await;
            }
            if deadline.expired() {
                return Err(Error::Timeout(blocked.unwrap_or(l.otg(p, FRAME_COUNT))));
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(10).as_instant()).await;
        }
    }
    pub(in crate::amdgpu_dcn401_otg) async fn start_blank(
        &mut self,
        pipe: u8,
        clock: dccg::Applied,
    ) -> Result<BlankRunning, Error> {
        self.preflight(pipe, false)?;
        let blank = self.status.blanks[usize::from(pipe)].ok_or(Error::Invalid)?;
        if blank.request.pipe != pipe || self.blank_timing(blank.request, clock)? != blank.timing {
            return Err(Error::Invalid);
        }
        let request = blank.timing.request;
        // TMDS currently has no retained, acknowledged PHY PLL owner.
        if request.signal == Signal::Tmds {
            return Err(Error::Unsupported);
        }
        request.validate_clock(clock)?;
        let plan = request.plan()?;
        let timeout_us = blank.timeout_us()?;
        self.fetchers_stopped()?;
        self.verify_blank(blank, plan, false)?;
        // Set before the first write/await. Dropping this future quarantines
        // timing and prevents ordinary retirement or any clock reprogramming.
        self.status.state = State::StartingBlank(pipe);
        let result = async {
            let running = self.enable_blank(blank, timeout_us).await?;
            let l = self.layout;
            for (at, mask) in l.idle {
                if at != l.otg(pipe, CONTROL)
                    && at != l.otg(pipe, CLOCK)
                    && !self.sibling_register(at)
                    && self.read(at)? & mask != 0
                {
                    return Err(Error::Busy);
                }
            }
            Ok(running)
        }
        .await;
        match result {
            Ok(running) => {
                self.status.running_blank = Some(running);
                self.status.state = State::RunningBlank(pipe);
                Ok(running)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Start the prepared internal black pattern with memory fetchers and all
    /// external streams stopped. Requires acknowledged native DTO clocks;
    /// TMDS is unsupported until a native PHY PLL owner exists. At most one
    /// timing generator runs; retire it before changing clocks or preparation.
    /// # Safety
    /// Stop CPU scanout writers and retain every associated surface, page
    /// table, HUBP and OPP resource, including inherited ones. Neither success
    /// nor failure permits freeing them or enabling a plane/link. Exclude all
    /// concurrent fetcher/metadata/cursor writers as well as firmware/FAMS.
    pub async unsafe fn start_blank(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        pipe: u8,
    ) -> Result<BlankRunning, Error> {
        if !self.0.status.state.reusable() {
            return Err(Error::Busy);
        }
        if pipe >= 4 {
            return Err(Error::Invalid);
        }
        let (held, layout) = self.0.held();
        let clock = dccg
            .timing_clock_except(self.0.io.0, clocks, pipe, &|at| {
                held_by_sibling(held, layout, at)
            })
            .map_err(Error::PipeClocks)?;
        self.0.start_blank(pipe, clock).await
    }
}
