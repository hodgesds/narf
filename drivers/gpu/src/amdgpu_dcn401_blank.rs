//! Start internal black timing only, using native optc401_enable_crtc order.
//! No fetcher, MPC tree or link is enabled by this operation.
use super::*;

const FRAME_COUNT: u64 = 0x1b4d;
const FRAME_MASK: u32 = 0xffffff;
const HUBP_CONTROL: u64 = 0x5f4;
const HUBP_CLOCK: u64 = 0x5f5;
const CURSOR_CONTROL: u64 = 0x679;
const DMDATA_CONTROL: u64 = 0x685;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlankRunning {
    pub blank: BlankApplied,
    /// Two distinct 24-bit counters sampled after blank completion. Wrap is
    /// allowed. These are historical evidence, not a live vblank subscription.
    pub frame_before: u32,
    pub frame_after: u32,
}
impl Layout {
    fn hubp(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(pipe) * 0xdc) * 4
    }
}
impl<I: Io> Engine<I> {
    fn expect(&mut self, at: u64, mask: u32, value: u32) -> Result<(), Error> {
        if self.read(at)? & mask != value {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    fn fetchers_stopped(&mut self) -> Result<(), Error> {
        // Starting VTG must not wake inherited surface, cursor or metadata DMA.
        // Require positive no-outstanding-request acknowledgement, blank and
        // TTU disable on every HUBP, plus disabled fetch clocks/cursors/metadata.
        // Zero reads from a powered-off block do not satisfy this condition.
        // This is deliberately a precondition, not an inherited-plane teardown.
        let l = self.layout;
        for pipe in 0..4 {
            let at = |r| l.hubp(pipe, r);
            for (r, mask, value) in [
                (HUBP_CONTROL, 0x1007, 0x1003),
                (HUBP_CLOCK, 1, 0),
                (CURSOR_CONTROL, 1, 0),
                (DMDATA_CONTROL, 0x0fff0007, 0),
            ] {
                if self.read(at(r))? & mask != value {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(())
    }
    fn verify_blank(
        &mut self,
        blank: BlankApplied,
        plan: Plan,
        running: bool,
    ) -> Result<(), Error> {
        let l = self.layout;
        let p = blank.request.pipe;
        for (r, mask, value) in plan.registers() {
            self.expect(l.otg(p, r), mask, value)?;
        }
        for (at, mask, value) in [
            (l.otg(p, H_TIMING), 0x103, plan.h_divider()),
            (l.otg(p, V_CONTROL), 0xffff0013, 0),
            (l.otg(p, CLOCK), 0x113, 0x103),
            (l.odm(p, INPUT_CLOCK), 7, 7),
            (
                l.odm(p, SOURCE),
                0xffff0003,
                0xfff00000 | u32::from(p) << 16,
            ),
            (l.odm(p, MEMORY), 0xffff, 0),
            (l.odm(p, FORMAT), 0x33, 0),
            (l.vtg(p), 0xffff7fff, plan.vtg | u32::from(running) << 31),
            (l.opp(p, PIPE), 0x13, 3),
        ] {
            self.expect(at, mask, value)?;
        }
        for (r, mask, value) in blank.request.registers(plan.request.timing) {
            self.expect(l.opp(p, r), mask, value)?;
        }
        Ok(())
    }
    async fn enable_blank(
        &mut self,
        blank: BlankApplied,
        timeout_us: u64,
    ) -> Result<BlankRunning, Error> {
        let l = self.layout;
        let p = blank.request.pipe;
        let deadline = narf_time::Deadline::after_us(timeout_us);
        // Native DCN401 workaround requires VTG before master enable.
        self.update(l.odm(p, SOURCE), 0xf0000, u32::from(p) << 16)?;
        self.update(l.vtg(p), 0x80000000, 0x80000000)?;
        self.update(l.otg(p, CONTROL), 0x301, 0x201)?;
        let mut before = None;
        loop {
            // Recheck each witness together. A cleared pending bit without a
            // current master or a fresh subsequent frame cannot prove blanking.
            let blocked = if self.read(l.otg(p, CONTROL))? & 0x10001 != 0x10001 {
                Some(l.otg(p, CONTROL))
            } else if self.read(l.opp(p, PENDING))? & 1 != 0 {
                Some(l.opp(p, PENDING))
            } else if self.read(l.opp(p, FMT))? & 0x1000000 != 0 {
                Some(l.opp(p, FMT))
            } else {
                None
            };
            if blocked.is_some() {
                before = None;
            } else {
                let frame = self.read(l.otg(p, FRAME_COUNT))? & FRAME_MASK;
                if let Some(first) = before {
                    if frame != first {
                        self.fetchers_stopped()?;
                        self.verify_blank(blank, blank.timing.request.plan()?, true)?;
                        self.expect(l.otg(p, CONTROL), 0x10301, 0x10201)?;
                        for (at, mask) in l.idle {
                            if at != l.otg(p, CONTROL)
                                && at != l.otg(p, CLOCK)
                                && self.read(at)? & mask != 0
                            {
                                return Err(Error::Busy);
                            }
                        }
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
        let t = request.timing;
        let frame_us = (u64::from(t.h_total) * u64::from(t.v_total) * 1000)
            .div_ceil(u64::from(t.pixel_clock_khz));
        let timeout_us = frame_us * 3 + 5000;
        if timeout_us > 1_000_000 {
            return Err(Error::Invalid);
        }
        self.fetchers_stopped()?;
        self.verify_blank(blank, plan, false)?;
        // Set before the first write/await. Dropping this future quarantines
        // timing and prevents ordinary retirement or any clock reprogramming.
        self.status.state = State::StartingBlank(pipe);
        match self.enable_blank(blank, timeout_us).await {
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
        let clock = dccg
            .timing_clock(self.0.io.0, clocks, pipe)
            .map_err(Error::PipeClocks)?;
        self.0.start_blank(pipe, clock).await
    }
}
