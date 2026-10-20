//! Native DCN401 legacy SST frontend setup with video/timing still stopped.
//! Follows setup_dio_stream_encoder, enc401_dp_set_stream_attribute and
//! dccg401_enable_symclk_se. The frontend, OTG and PHY are independent indices.
use super::*;

#[path = "amdgpu_dcn401_dp_video.rs"]
mod video;
pub use video::DpVideoRunning;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpFrontendRequest {
    pub stream: u8,
    pub pipe: u8,
    /// The sink takes colorimetry in the VSC SDP
    /// (stream->use_vsc_sdp_for_colorimetry): MSA MISC1 says so and the
    /// video sends mod_build_vsc_infopacket's revision-5 SDP.
    pub vsc_colorimetry: bool,
    /// The HDR static metadata SDP (amdgpu_dm_fill_hdr_info_packet), sent
    /// in GSP3 every frame while HDR_OUTPUT_METADATA is set.
    pub hdr: Option<crate::amdgpu_hdr::InfoPacket>,
}
impl DpFrontendRequest {
    /// The plain SST/MST stream: no VSC colorimetry, no HDR SDP.
    pub fn new(stream: u8, pipe: u8) -> Self {
        Self {
            stream,
            pipe,
            vsc_colorimetry: false,
            hdr: None,
        }
    }
    /// What the video owner holds of DP_SEC_CNTL for its info packets:
    /// GSP0 (VSC) and GSP3 (HDR), each with the secondary stream master.
    pub(in crate::amdgpu_dcn401_otg) fn sdp_enables(self) -> u32 {
        let vsc = if self.vsc_colorimetry { 1 << 20 | 1 } else { 0 };
        let hdr = if self.hdr.is_some() { 1 << 23 | 1 } else { 0 };
        vsc | hdr
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpFrontendReady {
    pub request: DpFrontendRequest,
    pub link: DpLinkTrained,
    pub blank: BlankApplied,
    pub pixels_per_cycle: u8,
    controls: [u32; 15],
    clock_routes: [u32; 4],
    backend_routes: [u32; 4],
}
impl DpFrontendReady {
    fn registers(self, l: Layout) -> [(u64, u32); 15] {
        let at = |r| DpStream::Dio(self.request.stream).at(l, r);
        [
            (at(0x2093), 0x177),  // source, stereo source and gate
            (at(0x2094), 0x2037), // mode/request/reset; TMDS clock must stay off
            (at(0x2095), 1),
            (at(0x209b), 0x3ff), // FIFO controls; independent RESET_DONE below
            // Stream mappers are contiguous, NOT in the DIO stride.
            (l.base + (0x1f0d + u64::from(self.request.stream)) * 4, 7),
            (at(0x211f), 0x10731),
            (at(0x2120), u32::MAX),
            (at(0x2124), u32::MAX),
            (at(0x2162), u32::MAX),
            (at(0x2163), u32::MAX),
            (at(0x2164), u32::MAX),
            (at(0x2165), u32::MAX),
            (at(0x2146), 1),
            (at(0x2123), 7),
            (at(0x2122), 0x10301),
        ]
    }
}
impl<I: Io> Engine<I> {
    fn dp_frontend_verify(&mut self, plan: DpFrontendReady) -> Result<(), Error> {
        self.dp_frontend_verify_source(plan, None, false)?;
        let l = self.layout;
        let r = plan.request;
        self.verify_blank(plan.blank, plan.blank.timing.request.plan()?, false)?;
        if self.read(l.otg(r.pipe, CONTROL))? & 0x10001 != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    // Only the video owner may exempt its timing and a pending video status
    // from idle checks. It validates timing/OPP/fetchers and the video request
    // independently; every other stream, route and PHY remains checked here.
    fn dp_frontend_verify_source(
        &mut self,
        plan: DpFrontendReady,
        timing: Option<u8>,
        video_pending: bool,
    ) -> Result<(), Error> {
        let l = self.layout;
        let r = plan.request;
        self.dp_training_verify_owned(plan.link, Some(r.stream), timing)?;
        if self.read(l.otg(r.pipe, LOCK))? & 0x101 != 0 {
            return Err(Error::Busy);
        }
        for (i, ((at, mut mask), expected)) in
            plan.registers(l).into_iter().zip(plan.controls).enumerate()
        {
            if i == 14 && video_pending {
                mask &= !0x10000;
            }
            if self.read(at)? & mask != expected & mask {
                return Err(Error::Readback(at));
            }
        }
        // Other displays route their own streams and backends after this
        // snapshot, and release them when they stop: every other route
        // stays as it was or is released. This display's own stream and
        // backend routes stay exactly as programmed. An MST backend permits
        // the currently owned sibling selections, but no foreign frontend.
        let others = self.displays.siblings;
        let phy = plan.link.phy.path.transmitter;
        for b in 0..4 {
            let shared = b == phy && plan.link.phy.settings.mst;
            let backend_mask = if shared {
                0x7f00 & !(u32::from(others.streams) << 8)
            } else {
                0x7f00
            };
            for (at, mask, value, theirs, own) in [
                (
                    l.dio_clock + u64::from(b) * 4,
                    0x711,
                    plan.clock_routes[usize::from(b)],
                    others.streams & bit(b) != 0,
                    b == r.stream,
                ),
                (
                    DpStream::Dio(b).at(l, 0x20bc),
                    backend_mask,
                    if shared {
                        plan.backend_routes[usize::from(b)] & (0x100 << r.stream)
                    } else {
                        plan.backend_routes[usize::from(b)]
                    },
                    others.transmitters & bit(b) != 0 && b != phy,
                    b == phy,
                ),
            ] {
                let now = self.read(at)? & mask;
                if !theirs && now != value & mask && (own || now != 0) {
                    return Err(Error::Readback(at));
                }
            }
        }
        let at = |reg| DpStream::Dio(r.stream).at(l, reg);
        // Packet/audio/metadata, DSC/VBID overrides and double-buffered format
        // programming need separate owners. Never wake an inherited producer.
        // The audio owner's packet enables are its own while it runs.
        let audio = if self.status.dp_audio.is_some() {
            super::hdmi_link::audio::DP_SEC_AUDIO
        } else {
            0
        };
        // A DSC stream's PPS SDP (GSP11 and the secondary stream) is the
        // video owner's.
        let dsc = plan.blank.timing.request.dsc.is_some();
        let pps = if dsc { 1 } else { 0 };
        // So are its VSC and HDR SDPs (GSP0, GSP3).
        let sdp = plan.request.sdp_enables();
        for (reg, mask) in [
            (0x2141, 0x1ff11111 & !audio & !pps & !sdp),
            (0x2091, 0x1010),
            (0x213d, 0x11),
            (0x2170, 0x3010),
        ] {
            if self.read(at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        for reg in 0x2174..=0x2177 {
            let mask = if dsc && reg == 0x2177 { 0x308f } else { 0x309f };
            if self.read(at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn dp_frontend_update(
        &mut self,
        plan: &mut DpFrontendReady,
        slot: usize,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.dp_frontend_verify(*plan)?;
        self.update(plan.registers(self.layout)[slot].0, mask, value)?;
        plan.controls[slot] = (plan.controls[slot] & !mask) | value;
        Ok(())
    }
    fn dp_frontend_route(
        &mut self,
        plan: &mut DpFrontendReady,
        connect: bool,
    ) -> Result<(), Error> {
        self.dp_frontend_verify(*plan)?;
        let phy = plan.link.phy.path.transmitter;
        let own = 0x100 << plan.request.stream;
        let value = if connect { own } else { 0 };
        // dcn10_link_encoder_connect_dig_be_to_fe: an MST backend keeps the
        // other streams' selections; an SST one takes this frontend alone.
        let mask = if plan.link.phy.settings.mst {
            own
        } else {
            0x7f00
        };
        self.update(DpStream::Dio(phy).at(self.layout, 0x20bc), mask, value)?;
        plan.link.phy.controls[1] = (plan.link.phy.controls[1] & !mask) | value;
        plan.backend_routes[usize::from(phy)] =
            (plan.backend_routes[usize::from(phy)] & !mask) | value;
        Ok(())
    }
    fn dp_frontend_clock_route(
        &mut self,
        plan: &mut DpFrontendReady,
        enable: bool,
    ) -> Result<(), Error> {
        self.dp_frontend_verify(*plan)?;
        let stream = usize::from(plan.request.stream);
        let value = if enable {
            0x10 | u32::from(plan.link.phy.path.transmitter) << 8
        } else {
            0
        };
        self.update(self.layout.dio_clock + stream as u64 * 4, 0x710, value)?;
        plan.clock_routes[stream] = (plan.clock_routes[stream] & !0x710) | value;
        Ok(())
    }
    fn dp_frontend_plan(
        &mut self,
        path: Path,
        request: DpFrontendRequest,
        clock: dccg::Applied,
    ) -> Result<DpFrontendReady, Error> {
        if self.status.state != State::DpLinkTrained(path.transmitter) {
            return Err(Error::Busy);
        }
        if request.stream >= 4 || request.pipe >= 4 {
            return Err(Error::Invalid);
        }
        let link = self.status.dp_link_trained.ok_or(Error::Invalid)?;
        if link.phy.path != path {
            return Err(Error::Invalid);
        }
        self.dp_training_verify(link)?;
        let blank = self.status.blanks[usize::from(request.pipe)].ok_or(Error::Invalid)?;
        if self.blank_timing(blank.request, clock)? != blank.timing
            || blank.request.pipe != request.pipe
        {
            return Err(Error::Invalid);
        }
        let timing = blank.timing.request;
        if timing.signal != Signal::DisplayPort {
            return Err(Error::Unsupported);
        }
        timing.validate_clock(clock)?;
        timing.plan()?;
        let bpc = match blank.request.depth {
            ColorDepth::Bpc8 => 8,
            ColorDepth::Bpc10 => 10,
            ColorDepth::Bpc12 => 12,
        };
        // Necessary payload ceiling only, not DML admission/watermark validation.
        let required = if let Some(cfg) = timing.dsc {
            // This native DSC path is RGB (SST or MST) with FEC, its PPS
            // at the stream's depth. Its validated PPS determines the
            // payload, including the per-slice overhead; comparing the
            // uncompressed pixels would reject the very modes which need
            // compression to fit their link.
            if !link.fec || u64::from(cfg.bpc) != bpc {
                return Err(Error::Unsupported);
            }
            u64::from(crate::amdgpu_dsc::dsc_kbps(
                &super::dsc_hw::dsc_timing(&timing.timing, cfg.bpc),
                cfg.bpp_x16,
                cfg.slices_h,
            ))
        } else {
            u64::from(timing.timing.pixel_clock_khz) * 3 * bpc
        };
        let raw = (link.phy.settings.rate as u64) * 27_000 * 8 * u64::from(link.phy.settings.lanes);
        // Linux dp_link_bandwidth_kbps: 97% of 8b/10b payload with FEC.
        let available = if link.fec { raw * 97 / 100 } else { raw };
        if required > available {
            return Err(Error::Unsupported);
        }
        if clock.reference_hz == 0 {
            return Err(Error::Invalid);
        }
        let pixel_hz = u64::from(timing.timing.pixel_clock_khz) * 1000;
        let pixels_per_cycle = [1, 2, 4, 8]
            .into_iter()
            .find(|&p| pixel_hz <= u64::from(clock.reference_hz) * u64::from(p))
            .ok_or(Error::Unsupported)?;
        let mut plan = DpFrontendReady {
            request,
            link,
            blank,
            pixels_per_cycle,
            controls: [0; 15],
            clock_routes: [0; 4],
            backend_routes: [0; 4],
        };
        for (i, (at, mask)) in plan.registers(self.layout).into_iter().enumerate() {
            plan.controls[i] = self.read(at)? & mask;
        }
        let l = self.layout;
        let at = |reg| DpStream::Dio(request.stream).at(l, reg);
        if self.read(at(0x2094))? & 0x2c30 != 0
            || self.read(at(0x209b))? & 0x100083 != 0
            || !matches!(plan.controls[13] & 6, 0 | 6)
            || plan.controls[7] & 0x3f != 0
        {
            return Err(Error::Busy);
        }
        for b in 0..4 {
            plan.clock_routes[usize::from(b)] =
                self.read(self.layout.dio_clock + u64::from(b) * 4)? & 0x711;
            plan.backend_routes[usize::from(b)] =
                self.read(DpStream::Dio(b).at(self.layout, 0x20bc))? & 0x7f00;
            if plan.backend_routes[usize::from(b)] & (0x7000 | (0x100 << request.stream)) != 0 {
                return Err(Error::Busy);
            }
        }
        if plan.clock_routes[usize::from(request.stream)] & 0x10 != 0 {
            return Err(Error::Busy);
        }
        self.dp_frontend_verify(plan)?;
        Ok(plan)
    }
    async fn dp_frontend_sink(
        &mut self,
        io: &mut impl Transport,
        plan: DpFrontendReady,
    ) -> Result<(), Error> {
        self.dp_frontend_verify(plan)?;
        sink_config(io, plan.link).await?;
        if read::<1>(io, plan.link.phy.path, 0x600).await?[0] & 7 != 1 {
            return Err(sink_readback(0x600));
        }
        if !eq_done(
            read::<6>(io, plan.link.phy.path, 0x202).await?,
            plan.link.phy.settings.lanes,
        ) {
            return Err(Error::DpTraining(DpTrainingError::LinkLost));
        }
        self.dp_frontend_verify(plan)
    }
    async fn dp_frontend_program(
        &mut self,
        io: &mut impl Transport,
        plan: &mut DpFrontendReady,
    ) -> Result<(), Error> {
        self.dp_frontend_sink(io, *plan).await?;
        self.dp_frontend_clock_route(plan, true)?;
        let t = plan.blank.timing.request.timing;
        let depth = match plan.blank.request.depth {
            ColorDepth::Bpc8 => 1,
            ColorDepth::Bpc10 => 2,
            ColorDepth::Bpc12 => 3,
        };
        // enc401_stream_encoder_dp_set_stream_attribute's MSA MISC0 and
        // MISC1 for the output color space (RGB: DP takes no 4:2:0 here).
        let (misc0, misc1) = crate::amdgpu_hdr::msa_misc(
            plan.blank.request.colorspace,
            crate::amdgpu_hdr::PixelEncoding::Rgb,
            6 + 2 * depth as u8,
            plan.request.vsc_colorimetry,
            plan.controls[7],
        );
        // Source/stereo selection is the OTG, never the physical port index.
        for (slot, mask, value) in [
            (0, 7, u32::from(plan.request.pipe)),
            (0, 0x70, u32::from(plan.request.pipe) << 4),
            (0, 0x100, 0x100),
            // PIXEL_ENCODING_TYPE: compressed for a DSC stream (RGB, so
            // COMPRESSED_PIXEL_FORMAT 0), as enc401's stream attribute sets.
            (
                5,
                0x10731,
                depth << 8 | u32::from(plan.blank.timing.request.dsc.is_some()),
            ),
            // MSA MISC0: component depth, bit 3 (CEA dynamic range) for
            // limited RGB and the YCbCr colorimetry bits.
            (6, u32::MAX, misc0 << 24),
            // MISC1: bit 6 when the VSC SDP carries colorimetry, bit 7
            // (Y-only) cleared for the sRGB/601/709 spaces.
            (7, 0xc0, misc1),
            (8, u32::MAX, t.h_total << 16 | t.v_total),
            (
                9,
                u32::MAX,
                (t.h_total - t.h_active - t.h_front_porch) << 16
                    | (t.v_total - t.v_active - t.v_front_porch),
            ),
            (
                10,
                u32::MAX,
                t.h_sync_width << 16
                    | u32::from(!t.h_sync_positive) << 31
                    | t.v_sync_width
                    | u32::from(!t.v_sync_positive) << 15,
            ),
            (11, u32::MAX, t.h_active << 16 | t.v_active),
            (12, 1, 0), // no secondary packet producer or splitting
            (13, 1, 0), // video remains stopped; do not release steering reset
        ] {
            self.dp_frontend_update(plan, slot, mask, value)?;
        }
        self.dp_frontend_route(plan, true)?;
        // enc401 dp enable: DIG_FE_MODE DP SST (0) or DP MST (5).
        let mode = if plan.link.phy.settings.mst { 5 } else { 0 };
        self.dp_frontend_update(plan, 1, 7, mode)?;
        self.dp_frontend_update(plan, 1, 0x10, 0x10)?;
        self.dp_frontend_update(plan, 2, 1, 1)?;
        let at = DpStream::Dio(plan.request.stream).at(self.layout, 0x2094);
        self.wait(at, 0x2c30, 0xc10, 1000).await?;
        self.dp_frontend_update(plan, 4, 7, u32::from(plan.link.phy.path.transmitter))?;
        self.dp_frontend_update(plan, 3, 0x300, plan.pixels_per_cycle.trailing_zeros() << 8)?;
        self.dp_frontend_update(plan, 3, 0x7c, 7 << 2)?;
        // Native resync FIFO reset: request and acknowledgement in both directions.
        let fifo = DpStream::Dio(plan.request.stream).at(self.layout, 0x209b);
        self.dp_frontend_update(plan, 3, 2, 2)?;
        self.wait(fifo, 0x100002, 0x100002, 50_000).await?;
        self.dp_frontend_update(plan, 3, 2, 0)?;
        self.wait(fifo, 0x100002, 0, 50_000).await?;
        self.dp_frontend_update(plan, 3, 1, 1)?;
        self.dp_frontend_sink(io, *plan).await?;
        self.dp_frontend_settled(*plan, true)
    }
    fn dp_frontend_settled(&mut self, plan: DpFrontendReady, enabled: bool) -> Result<(), Error> {
        self.dp_frontend_verify(plan)?;
        for (r, mask, expected) in [
            (0x2094, 0x2c30, if enabled { 0xc10 } else { 0 }),
            (0x209b, 0x100003, u32::from(enabled)),
        ] {
            let at = DpStream::Dio(plan.request.stream).at(self.layout, r);
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_dp_frontend(
        &mut self,
        io: &mut impl Transport,
        path: Path,
        request: DpFrontendRequest,
        clock: dccg::Applied,
    ) -> Result<DpFrontendReady, Error> {
        if !io.ready() {
            return Err(Error::Busy);
        }
        let mut plan = self.dp_frontend_plan(path, request, clock)?;
        self.status.state = State::PreparingDpFrontend(request.stream);
        match self.dp_frontend_program(io, &mut plan).await {
            Ok(()) => {
                self.status.dp_frontend_ready = Some(plan);
                self.status.state = State::DpFrontendReady(request.stream);
                Ok(plan)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    pub(in crate::amdgpu_dcn401_otg) async fn stop_dp_frontend(
        &mut self,
        path: Path,
    ) -> Result<(), Error> {
        let mut plan = self.status.dp_frontend_ready.ok_or(Error::Invalid)?;
        if self.status.state != State::DpFrontendReady(plan.request.stream) {
            return Err(Error::Busy);
        }
        if plan.link.phy.path != path {
            return Err(Error::Invalid);
        }
        self.dp_frontend_settled(plan, true)?;
        self.status.state = State::StoppingDpFrontend(plan.request.stream);
        let result = async {
            self.dp_frontend_update(&mut plan, 3, 1, 0)?;
            self.dp_frontend_update(&mut plan, 2, 1, 0)?;
            self.dp_frontend_update(&mut plan, 1, 0x10, 0)?;
            self.wait(
                DpStream::Dio(plan.request.stream).at(self.layout, 0x2094),
                0x2c30,
                0,
                1000,
            )
            .await?;
            self.dp_frontend_settled(plan, false)?;
            self.dp_frontend_update(&mut plan, 3, 0x300, 0)?;
            self.dp_frontend_route(&mut plan, false)?;
            self.dp_frontend_clock_route(&mut plan, false)?;
            self.dp_frontend_settled(plan, false)?;
            // Restored streamless training evidence is checked live, not minted
            // from a cached frontend completion after clocks or routes changed.
            let trained = self.status.dp_link_trained.ok_or(Error::Invalid)?;
            if plan.link != trained {
                return Err(Error::Invalid);
            }
            self.dp_training_verify(trained)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.state = State::DpLinkTrained(path.transmitter);
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
    /// Prepare one full-range RGB SST frontend for matching staged black timing.
    /// # Safety
    /// Fulfil train_dp_link's direct-port and writer/resource obligations. Retain
    /// exclusive timing/clock/OPP ownership. Video and timing remain stopped;
    /// payload capacity alone is not bandwidth/watermark or scanout admission.
    pub(crate) async unsafe fn prepare_dp_frontend(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        io: &mut dmub::Dmub,
        path: Path,
        request: DpFrontendRequest,
    ) -> Result<DpFrontendReady, Error> {
        if self.0.status.state != State::DpLinkTrained(path.transmitter) {
            return Err(Error::Busy);
        }
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        let clock = dccg
            .retained_timing_clock(self.0.io.0, clocks, request.pipe)
            .map_err(Error::PipeClocks)?;
        let history = self.0.status.dp_frontend_ready;
        let ready = self.0.prepare_dp_frontend(io, path, request, clock).await?;
        match dccg.retained_timing_clock(self.0.io.0, clocks, request.pipe) {
            Ok(current) if current == clock => Ok(ready),
            result => {
                let e = result
                    .err()
                    .map(Error::PipeClocks)
                    .unwrap_or(Error::Invalid);
                self.0.status.dp_frontend_ready = history;
                self.0.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// Stop only this owner's prepared frontend, leaving the trained PHY live.
    /// # Safety
    /// Keep video/timing stopped, exclude all external writers and retain all
    /// allocations/translations. Error/cancellation requires independent recovery.
    pub(crate) async unsafe fn stop_dp_frontend(&mut self, path: Path) -> Result<(), Error> {
        self.0.stop_dp_frontend(path).await
    }
}
