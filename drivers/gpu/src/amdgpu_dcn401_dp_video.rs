//! Native legacy SST black video: optc401_enable/disable_crtc and
//! enc401_stream_encoder_dp_unblank / enc1_stream_encoder_dp_blank.
use super::*;

const VID_TIMING: u64 = 0x2126;
const VID_N: u64 = 0x2127;
const VID_M: u64 = 0x2128;
const MN_MASK: u32 = 0xff00f110;
const NVID: u32 = 0x8000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpVideoRunning {
    pub frontend: DpFrontendReady,
    /// Fresh frame progress after video acknowledgement and sink revalidation.
    pub timing: BlankRunning,
    /// Initial ratio only: hardware auto measurement may subsequently change M.
    pub mvid: u32,
    pub nvid: u32,
    mn: [u32; 2],
}
#[derive(Clone, Copy)]
struct Work {
    frontend: DpFrontendReady,
    timing: bool,
    pending: bool,
    mn: [u32; 2],
}
impl Work {
    fn at(self, l: Layout, reg: u64) -> u64 {
        DpStream::Dio(self.frontend.request.stream).at(l, reg)
    }
}
impl<I: Io> Engine<I> {
    fn dp_video_verify(&mut self, w: Work) -> Result<(), Error> {
        self.dp_video_verify_route(w, true)
    }
    fn dp_video_verify_route(&mut self, w: Work, connected: bool) -> Result<(), Error> {
        self.dp_video_verify_source(w, connected, None)
    }
    /// The running DP video stream with the owned surface as its live source.
    pub(in crate::amdgpu_dcn401_otg) fn dp_video_verify_scanout(
        &mut self,
        live: ScanoutRunning,
    ) -> Result<(), Error> {
        let running = self.status.dp_video_running.ok_or(Error::Invalid)?;
        if running.frontend.request.pipe != live.pipe
            || running.frontend.request.stream != live.stream
        {
            return Err(Error::Invalid);
        }
        let w = Work {
            frontend: running.frontend,
            timing: true,
            pending: false,
            mn: running.mn,
        };
        self.dp_video_verify_source(w, true, Some(live))
    }
    fn dp_video_verify_source(
        &mut self,
        w: Work,
        connected: bool,
        live: Option<ScanoutRunning>,
    ) -> Result<(), Error> {
        let l = self.layout;
        let p = w.frontend.request.pipe;
        self.dp_frontend_verify_source(w.frontend, w.timing.then_some(p), w.pending)?;
        self.fetchers_stopped_except(live)?;
        self.verify_blank_source(
            w.frontend.blank,
            w.frontend.blank.timing.request.plan()?,
            w.timing,
            connected,
            live.is_some(),
        )?;
        for (at, mask, expected) in [
            (
                l.otg(p, CONTROL),
                if w.timing { 0x10301 } else { 0x10001 },
                if w.timing { 0x10201 } else { 0 },
            ),
            (w.at(l, 0x2094), 0x2c30, 0xc10),
            (w.at(l, VID_TIMING), MN_MASK, w.mn[0]),
            (w.at(l, VID_N), 0xffffff, w.mn[1]),
        ] {
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
        }
        if w.timing {
            for (at, mask) in [(l.opp(p, 0x185b), 1), (l.opp(p, 0x1840), 0x1000000)] {
                if self.read(at)? & mask != 0 {
                    return Err(Error::Readback(at));
                }
            }
        }
        Ok(())
    }
    fn dp_video_update(
        &mut self,
        w: &mut Work,
        slot: usize,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.dp_video_verify(*w)?;
        self.update(w.frontend.registers(self.layout)[slot].0, mask, value)?;
        w.frontend.controls[slot] = (w.frontend.controls[slot] & !mask) | value;
        Ok(())
    }
    fn dp_video_mn(
        &mut self,
        w: &mut Work,
        slot: usize,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.dp_video_verify(*w)?;
        self.update(
            w.at(self.layout, if slot == 0 { VID_TIMING } else { VID_N }),
            mask,
            value,
        )?;
        w.mn[slot] = (w.mn[slot] & !mask) | value;
        Ok(())
    }
    async fn dp_video_sink(&mut self, io: &mut impl Transport, w: Work) -> Result<(), Error> {
        self.dp_video_verify(w)?;
        sink_config(io, w.frontend.link).await?;
        let path = w.frontend.link.phy.path;
        if read::<1>(io, path, 0x600).await?[0] & 7 != 1 {
            return Err(sink_readback(0x600));
        }
        if !eq_done(
            read::<6>(io, path, 0x202).await?,
            w.frontend.link.phy.settings.lanes,
        ) {
            return Err(Error::DpTraining(DpTrainingError::LinkLost));
        }
        self.dp_video_verify(w)
    }
    async fn dp_video_steer(&mut self, w: &mut Work, reset: bool) -> Result<(), Error> {
        self.dp_video_update(w, 13, 2, u32::from(reset) << 1)?;
        self.wait(
            w.at(self.layout, 0x2123),
            6,
            if reset { 6 } else { 0 },
            1000,
        )
        .await?;
        w.frontend.controls[13] = (w.frontend.controls[13] & !4) | u32::from(reset) << 2;
        self.dp_video_verify(*w)
    }
    fn dp_video_request(&mut self, w: &mut Work, enable: bool) -> Result<(), Error> {
        self.dp_video_update(w, 14, 0x301, 0x200 | u32::from(enable))?;
        w.pending = true;
        Ok(())
    }
    async fn dp_video_ack(
        &mut self,
        w: &mut Work,
        enable: bool,
        timeout: u64,
    ) -> Result<(), Error> {
        self.wait(
            w.at(self.layout, 0x2122),
            0x10001,
            if enable { 0x10001 } else { 0 },
            timeout,
        )
        .await?;
        w.frontend.controls[14] = (w.frontend.controls[14] & !0x10000) | u32::from(enable) << 16;
        w.pending = false;
        self.dp_video_verify(*w)
    }
    async fn dp_video_fifo(&mut self, w: &mut Work) -> Result<(), Error> {
        self.dp_video_update(w, 3, 0x7c, 7 << 2)?;
        self.dp_video_update(w, 3, 2, 2)?;
        self.wait(w.at(self.layout, 0x209b), 0x100002, 0x100002, 50_000)
            .await?;
        self.dp_video_update(w, 3, 2, 0)?;
        self.wait(w.at(self.layout, 0x209b), 0x100002, 0, 50_000)
            .await?;
        self.dp_video_update(w, 3, 1, 1)
    }
    fn dp_video_fifo_ready(&mut self, w: Work) -> Result<(), Error> {
        self.dp_video_verify(w)?;
        let at = w.at(self.layout, 0x209b);
        if self.read(at)? & 0x100003 != 1 {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    async fn dp_video_start(
        &mut self,
        io: &mut impl Transport,
        mut w: Work,
        mvid: u32,
    ) -> Result<DpVideoRunning, Error> {
        let timeout = w.frontend.blank.timeout_us()?;
        self.dp_video_sink(io, w).await?;
        self.enable_blank(w.frontend.blank, timeout).await?;
        w.timing = true;
        self.dp_video_verify(w)?;
        // Native RGB stream/link ratio: no component-depth or lane multiplier.
        self.dp_video_mn(&mut w, 0, 0x100, 0)?;
        self.dp_video_mn(&mut w, 1, 0xffffff, NVID)?;
        self.dp_video_verify(w)?;
        self.update(w.at(self.layout, VID_M), 0xffffff, mvid)?;
        let interval = w.frontend.pixels_per_cycle.trailing_zeros() << 14;
        self.dp_video_mn(&mut w, 0, 0xc000, interval)?;
        self.dp_video_mn(&mut w, 0, 0x100, 0x100)?;
        // Status must be off before steering reset. Keep native priming delays,
        // even when the model/hardware acknowledges individual requests early.
        self.dp_video_update(&mut w, 14, 1, 0)?;
        self.dp_video_ack(&mut w, false, 50_000).await?;
        self.dp_video_steer(&mut w, true).await?;
        io.delay(10).await;
        self.dp_video_steer(&mut w, false).await?;
        self.dp_video_update(&mut w, 13, 1, 1)?;
        self.dp_video_request(&mut w, true)?;
        io.delay(200).await;
        self.dp_video_fifo(&mut w).await?;
        io.delay(100).await;
        self.dp_video_request(&mut w, true)?;
        self.dp_video_ack(&mut w, true, timeout).await?;
        self.dp_video_sink(io, w).await?;
        let timing = self.wait_blank_frames(w.frontend.blank, timeout).await?;
        self.dp_video_fifo_ready(w)?;
        Ok(DpVideoRunning {
            frontend: w.frontend,
            timing,
            mvid,
            nvid: NVID,
            mn: w.mn,
        })
    }
    pub(in crate::amdgpu_dcn401_otg) async fn start_dp_video(
        &mut self,
        io: &mut impl Transport,
        path: Path,
        clock: dccg::Applied,
    ) -> Result<DpVideoRunning, Error> {
        let frontend = self.status.dp_frontend_ready.ok_or(Error::Invalid)?;
        if self.status.state != State::DpFrontendReady(frontend.request.stream) || !io.ready() {
            return Err(Error::Busy);
        }
        if frontend.link.phy.path != path || frontend.blank.timing.clock != clock {
            return Err(Error::Invalid);
        }
        frontend.blank.timing.request.validate_clock(clock)?;
        frontend.blank.timeout_us()?;
        self.dp_frontend_settled(frontend, true)?;
        let l = self.layout;
        let at = |r| DpStream::Dio(frontend.request.stream).at(l, r);
        let mn = [
            self.read(at(VID_TIMING))? & MN_MASK,
            self.read(at(VID_N))? & 0xffffff,
        ];
        // The prepared, video-off frontend owns its measurement generator;
        // native startup disables it before reseeding. Non-default dividers or
        // buffered M/N updates are outside this progressive RGB path.
        if mn[0] & !0xc100 != 0 {
            return Err(Error::Busy);
        }
        let mvid = (u64::from(NVID)
            * u64::from(frontend.blank.timing.request.timing.pixel_clock_khz)
            / (frontend.link.phy.settings.rate as u64 * 27_000)) as u32;
        if mvid == 0 || mvid > 0xffffff {
            return Err(Error::Invalid);
        }
        let w = Work {
            frontend,
            timing: false,
            pending: false,
            mn,
        };
        self.dp_video_fifo_ready(w)?;
        self.status.state = State::StartingDpVideo(frontend.request.stream);
        match self.dp_video_start(io, w, mvid).await {
            Ok(running) => {
                self.status.dp_video_running = Some(running);
                self.status.state = State::DpVideoRunning(frontend.request.stream);
                Ok(running)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    pub(in crate::amdgpu_dcn401_otg) async fn stop_dp_video(
        &mut self,
        path: Path,
    ) -> Result<(), Error> {
        let running = self.status.dp_video_running.ok_or(Error::Invalid)?;
        let frontend = running.frontend;
        if self.status.state != State::DpVideoRunning(frontend.request.stream) {
            return Err(Error::Busy);
        }
        if frontend.link.phy.path != path {
            return Err(Error::Invalid);
        }
        let mut w = Work {
            frontend,
            timing: true,
            pending: false,
            mn: running.mn,
        };
        self.dp_video_fifo_ready(w)?;
        self.status.state = State::StoppingDpVideo(frontend.request.stream);
        let result = async {
            // Keep timing and both clocks alive through video-off acknowledgement.
            self.dp_video_request(&mut w, false)?;
            self.dp_video_ack(&mut w, false, frontend.blank.timeout_us()?)
                .await?;
            self.dp_video_steer(&mut w, true).await?;
            self.dp_video_update(&mut w, 13, 1, 0)?;
            self.dp_video_mn(&mut w, 0, 0x100, 0)?;
            self.dp_video_fifo_ready(w)?;
            self.disable(frontend.request.pipe).await?;
            w.timing = false;
            self.dp_video_verify_route(w, false)?;
            // After native master-off AND busy-off, restage the single OPP
            // route. No timing enable: the existing frontend owner can now
            // either restart black video or perform its normal link shutdown.
            self.update(
                self.layout.odm(frontend.request.pipe, SOURCE),
                0xf0000,
                u32::from(frontend.request.pipe) << 16,
            )?;
            self.dp_video_fifo_ready(w)?;
            self.dp_frontend_settled(w.frontend, true)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.dp_frontend_ready = Some(w.frontend);
                self.status.state = State::DpFrontendReady(frontend.request.stream);
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Start the prepared RGB black pattern on this owner's trained legacy SST
    /// link. Does not enable memory fetchers or claim sink presentation.
    /// # Safety
    /// Fulfil prepare_dp_frontend's direct-port/clock/resource obligations and
    /// exclude every external timing, fetcher, packet, PHY and firmware writer
    /// throughout the running lifetime. Retain all allocations/translations.
    pub(crate) async unsafe fn start_dp_video(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        io: &mut dmub::Dmub,
        path: Path,
    ) -> Result<DpVideoRunning, Error> {
        let fe = self.0.status.dp_frontend_ready.ok_or(Error::Invalid)?;
        if self.0.status.state != State::DpFrontendReady(fe.request.stream) {
            return Err(Error::Busy);
        }
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        let clock = dccg
            .retained_timing_clock(self.0.io.0, clocks, fe.request.pipe)
            .map_err(Error::PipeClocks)?;
        let history = self.0.status.dp_video_running;
        let running = self.0.start_dp_video(io, path, clock).await?;
        if let Err(e) = self.dp_video_clock(clocks, dccg, fe) {
            self.0.status.dp_video_running = history;
            return Err(e);
        }
        Ok(running)
    }
    fn dp_video_clock(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        fe: DpFrontendReady,
    ) -> Result<(), Error> {
        match dccg.retained_timing_clock(self.0.io.0, clocks, fe.request.pipe) {
            Ok(c) if c == fe.blank.timing.clock => Ok(()),
            result => {
                let e = result
                    .err()
                    .map(Error::PipeClocks)
                    .unwrap_or(Error::Invalid);
                self.0.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// Blank this owner's video, stop timing and return to the prepared frontend.
    /// # Safety
    /// Preserve start_dp_video's exclusive ownership and resource lifetimes.
    /// Failure/cancellation retains resources and requires independent recovery.
    pub(crate) async unsafe fn stop_dp_video(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        path: Path,
    ) -> Result<(), Error> {
        let fe = self
            .0
            .status
            .dp_video_running
            .ok_or(Error::Invalid)?
            .frontend;
        if self.0.status.state != State::DpVideoRunning(fe.request.stream) {
            return Err(Error::Busy);
        }
        self.dp_video_clock(clocks, dccg, fe)?;
        let history = self.0.status.dp_frontend_ready;
        self.0.stop_dp_video(path).await?;
        if let Err(e) = self.dp_video_clock(clocks, dccg, fe) {
            self.0.status.dp_frontend_ready = history;
            return Err(e);
        }
        Ok(())
    }
}
