//! Native TMDS HDMI black video on a prepared link: optc401_enable_crtc, the
//! second setup_dio_stream_encoder FIFO reset of dcn401_enable_stream (now with
//! symclk live), then dcn30_set_avmute(false). Stopping mutes first and holds
//! three frames, as dcn30_set_avmute(true) does, before the timing stops.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdmiVideoRunning {
    pub link: HdmiLinkReady,
    /// Fresh frame progress after the FIFO restarted under live timing.
    pub timing: BlankRunning,
}
impl<I: Io> Engine<I> {
    fn hdmi_video_verify(
        &mut self,
        link: HdmiLinkReady,
        live: Option<ScanoutRunning>,
    ) -> Result<(), Error> {
        self.hdmi_link_verify(link, true)?;
        self.fetchers_stopped_except(live)?;
        let blank = link.blank;
        self.verify_blank_source(
            blank,
            blank.timing.request.plan()?,
            true,
            true,
            live.is_some(),
        )?;
        let l = self.layout;
        let p = link.request.pipe;
        for (at, mask, value) in [
            (l.otg(p, CONTROL), 0x10301, 0x10201),
            (l.opp(p, 0x185b), 1, 0),
            (l.opp(p, 0x1840), 0x1000000, 0),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// The running HDMI video with the owned surface as its live source.
    pub(in crate::amdgpu_dcn401_otg) fn hdmi_video_verify_scanout(
        &mut self,
        live: ScanoutRunning,
    ) -> Result<(), Error> {
        let running = self.status.hdmi_video_running.ok_or(Error::Invalid)?;
        if running.link.request.pipe != live.pipe || running.link.request.stream != live.stream {
            return Err(Error::Invalid);
        }
        self.hdmi_video_verify(running.link, Some(live))
    }
    async fn hdmi_avmute(&mut self, link: &mut HdmiLinkReady, mute: bool) -> Result<(), Error> {
        self.hdmi_video_verify(*link, None)?;
        let at = link.registers(self.layout)[13].0;
        self.update(at, 1, u32::from(mute))?;
        link.controls[13] = u32::from(mute);
        self.hdmi_video_verify(*link, None)
    }
    async fn hdmi_video_start(
        &mut self,
        mut link: HdmiLinkReady,
    ) -> Result<HdmiVideoRunning, Error> {
        let timeout = link.blank.timeout_us()?;
        self.hdmi_link_verify(link, false)?;
        self.enable_blank(link.blank, timeout).await?;
        self.hdmi_video_verify(link, None)?;
        self.hdmi_fifo(&mut link, true).await?;
        self.hdmi_avmute(&mut link, false).await?;
        let timing = self.wait_blank_frames(link.blank, timeout).await?;
        self.hdmi_video_verify(link, None)?;
        Ok(HdmiVideoRunning { link, timing })
    }
    pub(in crate::amdgpu_dcn401_otg) async fn start_hdmi_video(
        &mut self,
        path: Path,
        clock: dccg::Applied,
    ) -> Result<HdmiVideoRunning, Error> {
        let link = self.status.hdmi_link_ready.ok_or(Error::Invalid)?;
        if self.status.state != State::HdmiLinkReady(path.transmitter) {
            return Err(Error::Busy);
        }
        if link.path != path || link.blank.timing.clock != clock {
            return Err(Error::Invalid);
        }
        link.blank.timing.request.validate_clock(clock)?;
        self.fetchers_stopped()?;
        self.hdmi_link_verify(link, false)?;
        self.status.state = State::StartingHdmiVideo(link.request.stream);
        match self.hdmi_video_start(link).await {
            Ok(running) => {
                self.status.hdmi_video_running = Some(running);
                self.status.state = State::HdmiVideoRunning(link.request.stream);
                Ok(running)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    async fn hdmi_video_stop(&mut self, mut link: HdmiLinkReady) -> Result<HdmiLinkReady, Error> {
        let timeout = link.blank.timeout_us()?;
        self.hdmi_avmute(&mut link, true).await?;
        for _ in 0..3 {
            self.wait_blank_frames(link.blank, timeout).await?;
        }
        self.hdmi_video_verify(link, None)?;
        let p = link.request.pipe;
        self.disable(p).await?;
        // As after DP video: restage the single OPP route with the timing off.
        self.update(self.layout.odm(p, SOURCE), 0xf0000, u32::from(p) << 16)?;
        self.verify_blank(link.blank, link.blank.timing.request.plan()?, false)?;
        self.hdmi_link_verify(link, false)?;
        Ok(link)
    }
    pub(in crate::amdgpu_dcn401_otg) async fn stop_hdmi_video(
        &mut self,
        path: Path,
    ) -> Result<(), Error> {
        let running = self.status.hdmi_video_running.ok_or(Error::Invalid)?;
        if self.status.state != State::HdmiVideoRunning(running.link.request.stream) {
            return Err(Error::Busy);
        }
        if running.link.path != path {
            return Err(Error::Invalid);
        }
        self.hdmi_video_verify(running.link, None)?;
        self.status.state = State::StoppingHdmiVideo(running.link.request.stream);
        match self.hdmi_video_stop(running.link).await {
            Ok(link) => {
                self.status.hdmi_link_ready = Some(link);
                self.status.hdmi_video_running = None;
                self.status.state = State::HdmiLinkReady(path.transmitter);
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
    /// Start the prepared black timing on this owner's live HDMI link and
    /// release AVMUTE. Does not enable memory fetchers.
    /// # Safety
    /// prepare_hdmi_link's obligations, held for the running lifetime.
    pub(crate) async unsafe fn start_hdmi_video(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        path: Path,
    ) -> Result<HdmiVideoRunning, Error> {
        let link = self.0.status.hdmi_link_ready.ok_or(Error::Invalid)?;
        let clock = dccg
            .retained_timing_clock(self.0.io.0, clocks, link.request.pipe)
            .map_err(Error::PipeClocks)?;
        let history = self.0.status.hdmi_video_running;
        let running = self.0.start_hdmi_video(path, clock).await?;
        if let Err(e) = self.hdmi_clock(clocks, dccg, link) {
            self.0.status.hdmi_video_running = history;
            return Err(e);
        }
        Ok(running)
    }
    fn hdmi_clock(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        link: HdmiLinkReady,
    ) -> Result<(), Error> {
        match dccg.retained_timing_clock(self.0.io.0, clocks, link.request.pipe) {
            Ok(c) if c == link.blank.timing.clock => Ok(()),
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
    /// Mute, stop timing and return to the prepared, transmitting link.
    /// # Safety
    /// start_hdmi_video's obligations; stop scanout first.
    pub(crate) async unsafe fn stop_hdmi_video(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        path: Path,
    ) -> Result<(), Error> {
        let link = self.0.status.hdmi_video_running.ok_or(Error::Invalid)?.link;
        self.hdmi_clock(clocks, dccg, link)?;
        self.0.stop_hdmi_video(path).await?;
        self.hdmi_clock(clocks, dccg, link)
    }
}
