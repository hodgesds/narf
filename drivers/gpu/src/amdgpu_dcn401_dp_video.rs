//! Native legacy SST black video: optc401_enable/disable_crtc and
//! enc401_stream_encoder_dp_unblank / enc1_stream_encoder_dp_blank.
use super::*;

const VID_TIMING: u64 = 0x2126;
const VID_N: u64 = 0x2127;
const VID_M: u64 = 0x2128;
const MN_MASK: u32 = 0xff00f110;
const NVID: u32 = 0x8000;
// Secondary data for a DSC stream's PPS SDP (DIG stride).
const SEC_CNTL: u64 = 0x2141;
const SEC_CNTL2: u64 = 0x2169;
const VBID_MISC: u64 = 0x2170;
const GSP11: u64 = 0x2177;
const AFMT_CNTL: u64 = 0x20ba;
/// DP_DSC_ENABLE.
const DSC_ENABLE: u32 = 0x160;

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
        self.dp_video_verify_source(w, true, Some(live))?;
        if running.frontend.link.phy.settings.mst {
            if let Some(a) = self.status.dp_audio {
                self.dp_audio_verify(&running.frontend, &a)?;
            }
        }
        Ok(())
    }
    /// Fresh transport witnesses for audio; does not recurse into audio checks.
    pub(in crate::amdgpu_dcn401_otg) fn dp_audio_verify_transport(&mut self) -> Result<(), Error> {
        let v = self.status.dp_video_running.ok_or(Error::Invalid)?;
        let r = v.frontend.request;
        let live = match self.status.state {
            State::DpVideoRunning(s) if s == r.stream => None,
            State::ScanoutRunning(p) if p == r.pipe => {
                let live = self.status.scanout.ok_or(Error::Invalid)?;
                if live.pipe != p || live.stream != r.stream {
                    return Err(Error::Invalid);
                }
                Some(live)
            }
            _ => return Err(Error::Busy),
        };
        self.dp_video_verify_source(
            Work {
                frontend: v.frontend,
                timing: true,
                pending: false,
                mn: v.mn,
            },
            true,
            live,
        )
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
            for o in w.frontend.blank.timing.request.plan()?.opps() {
                for (at, mask) in [(l.opp(o, 0x185b), 1), (l.opp(o, 0x1840), 0x1000000)] {
                    if self.read(at)? & mask != 0 {
                        return Err(Error::Readback(at));
                    }
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
    /// enc3_dp_set_dsc_pps_info_packet(true, immediate): the PPS in VPG
    /// generic packets 11-14 (type 0x10, 127 bytes), sent every frame on
    /// line 2 with VBID[6] updated on line 3.
    async fn dp_video_pps(&mut self, w: &Work) -> Result<(), Error> {
        let request = w.frontend.blank.timing.request;
        let Some(cfg) = request.dsc else {
            return Ok(());
        };
        let regs = super::dsc_hw::dsc_registers(&request, &cfg)?;
        let pps = crate::amdgpu_dsc::pack_pps(&regs.pps);
        let l = self.layout;
        let at = |r| w.at(l, r);
        self.update(at(SEC_CNTL2), 0x1000_0000, 0x1000_0000)?;
        self.update(at(AFMT_CNTL), 1, 1)?;
        if self.read(at(0x206d))? & 0x100 != 0 {
            self.update(at(0x206d), 0x11, 1)?;
            self.wait(at(0x206d), 0x100, 0, 1000).await?;
        }
        for (i, chunk) in pps.chunks_exact(32).enumerate() {
            let index = 11 + i as u32;
            self.wait(at(0x206c), 2, 0, 500).await?;
            self.access(|io| {
                // CONFLICT_CLR and the data port are commands, not state.
                let status = checked(io.read(at(0x206c)))?;
                io.write(at(0x206c), status | 0x10);
                let access = checked(io.read(at(0x2068)))?;
                io.write(at(0x2068), (access & !0xff) | (index * 9));
                io.write(at(0x2069), u32::from_le_bytes([0, 0x10, 127, 0]));
                for word in chunk.chunks_exact(4) {
                    io.write(
                        at(0x2069),
                        u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
                    );
                }
                let immediate = checked(io.read(at(0x206b)))?;
                io.write(at(0x206b), immediate | 1 << index);
                Ok(())
            })?;
        }
        self.update(at(GSP11), 0xffff_0000, 2 << 16)?;
        self.update(at(VBID_MISC), 0xffff_8000, 3 << 16)?;
        self.update(at(GSP11), 0x10, 0x10)?;
        self.update(at(SEC_CNTL), 1, 1)
    }
    /// enc3_stream_encoder_update_dp_info_packets for the stream's VSC SDP
    /// (packets 0 and 1, GSP0) and HDR metadata SDP (packet 3, GSP3):
    /// vpg3_update_generic_info_packet with immediate update for each valid
    /// packet, then the packet enables and the secondary stream master.
    async fn dp_video_infopackets(&mut self, w: &Work) -> Result<(), Error> {
        let r = w.frontend.request;
        let vsc = crate::amdgpu_hdr::vsc_sdp(
            r.vsc_colorimetry,
            w.frontend.blank.request.colorspace,
            crate::amdgpu_hdr::PixelEncoding::Rgb,
            match w.frontend.blank.request.depth {
                ColorDepth::Bpc8 => 8,
                ColorDepth::Bpc10 => 10,
                ColorDepth::Bpc12 => 12,
            },
            false,
        );
        if vsc.is_none() && r.hdr.is_none() {
            return Ok(());
        }
        let l = self.layout;
        let at = |reg| w.at(l, reg);
        if self.read(at(0x206d))? & 0x100 != 0 {
            self.update(at(0x206d), 0x11, 1)?;
            self.wait(at(0x206d), 0x100, 0, 1000).await?;
        }
        for (index, packet) in [(0u32, vsc), (1, vsc), (3, r.hdr)] {
            if let Some(p) = packet {
                self.dp_packet(r.stream, index, p).await?;
            }
        }
        self.update(at(SEC_CNTL), 1 << 20, u32::from(vsc.is_some()) << 20)?;
        self.update(at(SEC_CNTL), 1 << 23, u32::from(r.hdr.is_some()) << 23)?;
        if self.read(at(SEC_CNTL))? != 0 {
            self.update(at(SEC_CNTL), 1, 1)?;
        }
        Ok(())
    }
    /// vpg3_update_generic_info_packet(index, packet, immediate) on DIO
    /// stream encoder `stream`'s VPG.
    async fn dp_packet(
        &mut self,
        stream: u8,
        index: u32,
        packet: crate::amdgpu_hdr::InfoPacket,
    ) -> Result<(), Error> {
        let l = self.layout;
        let at = move |r| DpStream::Dio(stream).at(l, r);
        self.wait(at(0x206c), 2, 0, 500).await?;
        self.access(|io| {
            // CONFLICT_CLR and the data port are commands, not state.
            let status = checked(io.read(at(0x206c)))?;
            io.write(at(0x206c), status | 0x10);
            let access = checked(io.read(at(0x2068)))?;
            io.write(at(0x2068), (access & !0xff) | (index * 9));
            for word in packet.words() {
                io.write(at(0x2069), word);
            }
            let immediate = checked(io.read(at(0x206b)))?;
            io.write(at(0x206b), immediate | 1 << index);
            Ok(())
        })
    }
    /// enc3_stop_dp_info_packets for the VSC and HDR SDPs: their enables
    /// off, the secondary master kept while another packet (audio, PPS)
    /// still needs it.
    fn dp_video_infopackets_off(&mut self, w: &Work) -> Result<(), Error> {
        if w.frontend.request.sdp_enables() == 0 {
            return Ok(());
        }
        let at = w.at(self.layout, SEC_CNTL);
        self.update(at, 1 << 20 | 1 << 23, 0)?;
        if self.read(at)? & !1 == 0 {
            self.update(at, 1, 0)?;
        }
        Ok(())
    }
    /// New HDR metadata on the running DP stream (amdgpu_dm's
    /// hdr_static_metadata stream update): packet 3 rewritten with an
    /// immediate update. Entering or leaving HDR is a modeset; only a
    /// stream that already sends the SDP takes new contents here.
    pub(in crate::amdgpu_dcn401_otg) async fn dp_update_hdr(
        &mut self,
        packet: crate::amdgpu_hdr::InfoPacket,
    ) -> Result<(), Error> {
        let mut running = self.status.dp_video_running.ok_or(Error::Invalid)?;
        if running.frontend.request.hdr.is_none() || !packet.valid {
            return Err(Error::Invalid);
        }
        self.dp_packet(running.frontend.request.stream, 3, packet)
            .await?;
        running.frontend.request.hdr = Some(packet);
        self.status.dp_video_running = Some(running);
        if let Some(f) = self.status.dp_frontend_ready.as_mut() {
            f.request.hdr = Some(packet);
        }
        Ok(())
    }
    /// enc3_dp_set_dsc_pps_info_packet(false).
    fn dp_video_pps_off(&mut self, w: &Work) -> Result<(), Error> {
        if w.frontend.blank.timing.request.dsc.is_none() {
            return Ok(());
        }
        let l = self.layout;
        self.update(w.at(l, GSP11), 0x10, 0)?;
        self.update(w.at(l, SEC_CNTL2), 0x1000_0000, 0)
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
        // link_set_dpms_on after enable_stream: the sink decodes DSC
        // (dp_set_dsc_on_rx), then the PPS SDP, before unblanking.
        if w.frontend.blank.timing.request.dsc.is_some() {
            let path = w.frontend.link.phy.path;
            write(io, path, DSC_ENABLE, &mut [1]).await?;
            if read::<1>(io, path, DSC_ENABLE).await?[0] & 1 != 1 {
                return Err(sink_readback(DSC_ENABLE));
            }
            self.dp_video_pps(&w).await?;
            self.dp_video_verify(w)?;
        }
        // dcn20_update_info_frame before the unblank: VSC and HDR SDPs.
        self.dp_video_infopackets(&w).await?;
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
        io: &mut impl Transport,
        path: Path,
    ) -> Result<(), Error> {
        let running = self.status.dp_video_running.ok_or(Error::Invalid)?;
        let frontend = running.frontend;
        // Linux's link_set_dpms_off disables audio before the stream.
        if self.status.state != State::DpVideoRunning(frontend.request.stream)
            || self.status.dp_audio.is_some()
        {
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
            // link_set_dsc_enable(false): the sink stops decoding (unchecked,
            // as Linux ignores it), then the PPS SDP; disable() turns the
            // OPTC's DSC and the DSC off before the timing.
            if frontend.blank.timing.request.dsc.is_some() {
                let _ = write(io, path, DSC_ENABLE, &mut [0]).await;
                self.dp_video_pps_off(&w)?;
            }
            self.dp_video_infopackets_off(&w)?;
            self.disable(frontend.request.pipe).await?;
            w.timing = false;
            self.dp_video_verify_route(w, false)?;
            // After native master-off AND busy-off, restage the single OPP
            // route. No timing enable: the existing frontend owner can now
            // either restart black video or perform its normal link shutdown.
            self.restage_source(frontend.blank.timing.request)?;
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
impl<I: Io> Engine<I> {
    /// link_dpms.c enable_stream_features for a DP SST stream (8b/10b or
    /// 128b/132b) running on `path`: read DP_DOWNSPREAD_CTRL, set or clear
    /// IGNORE_MSA_TIMING_PARAM as the stream is VRR-capable, and write it back
    /// only when it changed. True when written. Busy unless SST video (or a
    /// scanout on it) runs on `path`; MST streams are refused (Linux defers
    /// them to dm_helpers_mst_enable_stream_features).
    pub(in crate::amdgpu_dcn401_otg) async fn dp_stream_features(
        &mut self,
        io: &mut impl Transport,
        path: Path,
        ignore_msa: bool,
    ) -> Result<bool, Error> {
        let s = &self.status;
        let running = matches!(
            s.state,
            State::DpVideoRunning(_) | State::UhbrVideoRunning(_) | State::ScanoutRunning(_)
        );
        let dio = s
            .dp_video_running
            .map(|v| (v.frontend.link.phy.path, v.frontend.link.phy.settings.mst));
        let hpo = s
            .uhbr_video_running
            .map(|v| (v.link.path, v.link.settings.mst));
        let Some((_, mst)) = [dio, hpo].into_iter().flatten().find(|&(p, _)| p == path) else {
            return Err(if running { Error::Invalid } else { Error::Busy });
        };
        if !running {
            return Err(Error::Busy);
        }
        if mst {
            return Err(Error::Unsupported);
        }
        use crate::amdgpu_freesync::{
            DPCD_DOWNSPREAD_CTRL as AT, DPCD_IGNORE_MSA_TIMING_PARAM as BIT,
        };
        let old = read::<1>(io, path, AT).await?[0];
        let new = if ignore_msa { old | BIT } else { old & !BIT };
        if new == old {
            return Ok(false);
        }
        write(io, path, AT, &mut [new]).await?;
        Ok(true)
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
    /// Set (or clear) the sink's IGNORE_MSA_TIMING_PARAM for the DP SST
    /// stream running on `path`, after its video started, as Linux's
    /// link_set_dpms_on does once the stream is unblanked; true when the
    /// DPCD byte changed. Linux ignores AUX failures here; callers may too.
    /// # Safety
    /// Preserve start_dp_video's (or start_uhbr_video's) exclusive ownership.
    pub(crate) async unsafe fn set_dp_ignore_msa(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
        ignore_msa: bool,
    ) -> Result<bool, Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.dp_stream_features(io, path, ignore_msa).await
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
        firmware: &mut dmub::Dmub,
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
        self.0.stop_dp_video(firmware, path).await?;
        if let Err(e) = self.dp_video_clock(clocks, dccg, fe) {
            self.0.status.dp_frontend_ready = history;
            return Err(e);
        }
        Ok(())
    }
}
