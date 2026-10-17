//! Native DCN401 HDMI FRL video: the single HPO FRL stream encoder (VPG4)
//! on a trained FRL link, as Linux brings it up: hpo_enc401_set_hdmi_
//! stream_attribute (pixel format, active/blank, borrow mode, packets per
//! line, general control, audio InfoFrame line), the AVI (and HDMI 1.4b
//! vendor) InfoFrame in VPG4 (hpo_enc401_update_hdmi_info_packets),
//! hpo_enc401_enable from the OTG, the timing running, hpo_enc401_unblank.
//! RGB or YCbCr black until a scanout takes over. The HDMISTREAMCLK half is the
//! clock owner's; this owner requires and rechecks it. Stop is Linux's
//! AVMUTE, hpo_enc401_blank and hpo_enc401_stop_hdmi_info_packets.
use super::*;
use crate::amdgpu_dcn401_otg::hdmi_link::{avi_infoframe, vendor_infoframe};
use crate::amdgpu_dcn_inventory::Path;

const PIXEL_FORMAT: u64 = 0x8e0;
const PACKET_CONTROL: u64 = 0x8e1;
const VBI_PACKET_CONTROL1: u64 = 0x8e3;
const GC_CONTROL: u64 = 0x8e5;
const GENERIC_CONTROL0: u64 = 0x8e6;
const GENERIC_LINE0_1: u64 = 0x8e9;
const H_ACTIVE_BLANK: u64 = 0x900;
const HC_ACTIVE_BLANK: u64 = 0x901;
const CRC: u64 = 0x903;
const MODE: u64 = 0x908;
const AFMT_INFOFRAME0: u64 = 0x92b;
// VPG4.
const VPG_ACCESS: u64 = 0x931;
const VPG_DATA: u64 = 0x932;
const VPG_IMMEDIATE: u64 = 0x934;
const VPG_STATUS: u64 = 0x935;
const VPG_MEM_PWR: u64 = 0x936;
/// HDMISTREAMCLK_CNTL (DCN bank 2).
const STREAM_CLOCK: u64 = 0x59;

/// What the FRL stream needs beyond its timing: Linux's capacity check's
/// borrow parameters at the trained link, and the AVI InfoFrame fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlVideoRequest {
    pub pipe: u8,
    pub audio_packets_line: u8,
    /// FRL_BORROW_MODE_FROM_BLANK rather than none.
    pub borrow_from_blank: bool,
    pub avi: Avi,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlVideoRunning {
    pub link: FrlLinkUp,
    pub request: FrlVideoRequest,
    pub timing: BlankRunning,
}
impl<I: Io> Engine<I> {
    /// The trained link, the clock owner's HDMISTREAMCLK from the pipe, and
    /// the staged (or running) timing.
    fn frl_video_verify(
        &mut self,
        link: &FrlLinkUp,
        blank: BlankApplied,
        running: bool,
    ) -> Result<(), Error> {
        if self.status.frl_link != Some(*link) {
            return Err(Error::Invalid);
        }
        self.frl_link_witnesses(link)?;
        let route = self.layout.base + STREAM_CLOCK * 4;
        if self.read(route)? & 15 != 8 | u32::from(blank.request.pipe) {
            return Err(Error::Readback(route));
        }
        let plan = blank.timing.request.plan()?;
        self.verify_blank_source(blank, plan, running, true, false)
    }
    /// hpo_enc401_set_hdmi_stream_attribute and set_dsc_config(NULL):
    /// uncompressed RGB or 4:2:0. The DTO keeps the full pixel rate;
    /// subsampled active/blank widths count pixel pairs in the encoder.
    fn frl_format_registers(blank: BlankApplied) -> [(u64, u32, u32); 3] {
        let t = blank.timing.request.timing;
        let y420 = u32::from(blank.request.ycbcr420);
        let (depth, deep) = match blank.request.depth {
            ColorDepth::Bpc8 => (0, 0),
            ColorDepth::Bpc10 => (1, 1),
            ColorDepth::Bpc12 => (2, 1),
        };
        [
            (PIXEL_FORMAT, 0x303_0301, y420 << 17 | depth << 8 | deep),
            (FIFO, 0x11100, y420 << 12),
            (
                H_ACTIVE_BLANK,
                u32::MAX,
                (t.h_active >> y420) | ((t.h_total - t.h_active) >> y420) << 16,
            ),
        ]
    }
    fn frl_verify_format(&mut self, blank: BlankApplied) -> Result<(), Error> {
        for (reg, mask, value) in Self::frl_format_registers(blank) {
            let at = self.frl_at(reg);
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// Program the uncompressed format and capacity-check borrow parameters.
    fn frl_stream_attribute(
        &mut self,
        request: FrlVideoRequest,
        blank: BlankApplied,
    ) -> Result<(), Error> {
        for (reg, mask, value) in Self::frl_format_registers(blank) {
            self.update(self.frl_at(reg), mask, value)?;
        }
        self.update(
            self.frl_at(MODE),
            3,
            if request.borrow_from_blank { 2 } else { 0 },
        )?;
        self.update(
            self.frl_at(PACKET_CONTROL),
            0x1f,
            u32::from(request.audio_packets_line),
        )?;
        self.update(self.frl_at(HC_ACTIVE_BLANK), u32::MAX, 0)?;
        // General control every frame, no ACP, the audio InfoFrame sent and
        // latched now, on line 2; AVMUTE off.
        self.update(self.frl_at(VBI_PACKET_CONTROL1), 0x1103, 0x1003)?;
        let afmt = self.frl_at(AFMT_INFOFRAME0);
        self.access(|io| {
            let v = checked(io.read(afmt))?;
            io.write(afmt, v | 0x80);
            Ok(())
        })?;
        self.update(self.frl_at(VBI_PACKET_CONTROL1), 0x7fff_0000, 2 << 16)?;
        self.update(self.frl_at(GC_CONTROL), 1, 0)
    }
    /// vpg31_poweron, then the AVI InfoFrame in generic packet 0 and, for
    /// an HDMI VIC, the vendor InfoFrame in 1: each written at its index,
    /// latched immediately, sent every frame on line 2.
    async fn frl_infoframes(
        &mut self,
        request: FrlVideoRequest,
        blank: BlankApplied,
    ) -> Result<(), Error> {
        if self.read(self.frl_at(VPG_MEM_PWR))? & 0x100 != 0 {
            self.update(self.frl_at(VPG_MEM_PWR), 0x11, 1)?;
            self.wait(self.frl_at(VPG_MEM_PWR), 0x100, 0, 1000).await?;
        }
        let t = blank.timing.request.timing;
        let avi = avi_infoframe(
            &t,
            request.avi,
            blank.request.limited,
            blank.request.ycbcr420,
        );
        let vendor = vendor_infoframe(&t, request.avi);
        let base = self.layout.mpc_base;
        for (index, packet) in [(0u32, Some(avi)), (1, vendor)] {
            let Some(packet) = packet else {
                continue;
            };
            self.wait(self.frl_at(VPG_STATUS), 2, 0, 500).await?;
            self.access(|io| {
                let at = |r: u64| base + r * 4;
                let status = checked(io.read(at(VPG_STATUS)))?;
                io.write(at(VPG_STATUS), status | 0x10);
                let access = checked(io.read(at(VPG_ACCESS)))?;
                io.write(at(VPG_ACCESS), (access & !0xff) | (index * 9));
                for word in packet.chunks_exact(4) {
                    io.write(
                        at(VPG_DATA),
                        u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
                    );
                }
                let immediate = checked(io.read(at(VPG_IMMEDIATE)))?;
                io.write(at(VPG_IMMEDIATE), immediate | 1 << index);
                Ok(())
            })?;
            self.update(
                self.frl_at(GENERIC_CONTROL0),
                3 << (4 * index),
                3 << (4 * index),
            )?;
            self.update(
                self.frl_at(GENERIC_LINE0_1),
                0x7fff << (16 * index),
                2 << (16 * index),
            )?;
        }
        Ok(())
    }
    /// hpo_enc401_enable from OTG `pipe`.
    async fn frl_stream_enable(&mut self, pipe: u8) -> Result<(), Error> {
        self.update(self.frl_at(CLOCK), 1, 1)?;
        self.update(self.frl_at(CONTROL), 0x11, 0x10)?;
        self.wait(self.frl_at(CONTROL), 0x100, 0x100, 1000).await?;
        self.update(self.frl_at(CONTROL), 0x10, 0)?;
        self.update(self.frl_at(CRC), 3, 3)?;
        self.update(self.frl_at(DB), 0x1000, 0x1000)?;
        self.update(self.frl_at(SOURCE), 7, u32::from(pipe))
    }
    /// hpo_enc401_unblank.
    async fn frl_unblank(&mut self) -> Result<(), Error> {
        self.update(self.frl_at(FIFO), 1, 0)?;
        self.update(self.frl_at(FIFO), 0x10, 0x10)?;
        self.wait(self.frl_at(FIFO), 0x10_0000, 0x10_0000, 10_000)
            .await?;
        self.update(self.frl_at(FIFO), 0x10, 0)?;
        self.wait(self.frl_at(FIFO), 0x10_0000, 0, 10_000).await?;
        self.update(self.frl_at(CONTROL), 1, 1)?;
        self.update(self.frl_at(FIFO), 1, 1)
    }
    async fn frl_video_start(
        &mut self,
        link: FrlLinkUp,
        request: FrlVideoRequest,
        blank: BlankApplied,
    ) -> Result<FrlVideoRunning, Error> {
        let timeout = blank.timeout_us()?;
        self.frl_stream_attribute(request, blank)?;
        self.frl_infoframes(request, blank).await?;
        self.frl_stream_enable(request.pipe).await?;
        self.frl_video_verify(&link, blank, false)?;
        self.enable_blank(blank, timeout).await?;
        self.frl_unblank().await?;
        self.frl_verify_format(blank)?;
        self.frl_video_verify(&link, blank, true)?;
        let timing = self.wait_blank_frames(blank, timeout).await?;
        let running = FrlVideoRunning {
            link,
            request,
            timing,
        };
        // Frame progress yielded after unblank: recheck the stream/link
        // witnesses before publishing the running owner.
        self.frl_video_verify_running(&running)?;
        Ok(running)
    }
    /// Start black RGB/4:2:0 video on the active FRL link from the prepared
    /// timing of `request.pipe`, whose HDMISTREAMCLK the clock owner has
    /// routed.
    pub(in crate::amdgpu_dcn401_otg) async fn start_frl_video(
        &mut self,
        path: Path,
        request: FrlVideoRequest,
        clock: dccg::Applied,
    ) -> Result<FrlVideoRunning, Error> {
        if self.status.state != State::FrlLinkActive(path.transmitter) {
            return Err(Error::Busy);
        }
        let link = self.status.frl_link.ok_or(Error::Invalid)?;
        let pipe = request.pipe;
        if link.path != path || pipe >= 4 || request.audio_packets_line > 0x1f {
            return Err(Error::Invalid);
        }
        let blank = self.status.blanks[usize::from(pipe)].ok_or(Error::Invalid)?;
        if self.blank_timing(blank.request, clock)? != blank.timing
            || blank.request.pipe != pipe
            || blank.timing.clock != clock
        {
            return Err(Error::Invalid);
        }
        let timing = blank.timing.request;
        if timing.signal != Signal::HdmiFrl {
            return Err(Error::Unsupported);
        }
        timing.validate_clock(clock)?;
        // The stream encoder starts quiet: clocks, FIFO, encoder and every
        // generic packet off.
        self.frl_packets_stopped()?;
        for (reg, mask) in [(CLOCK, 0x1111), (FIFO, 0x10_0011), (CONTROL, 0x111)] {
            if self.read(self.frl_at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        self.frl_video_verify(&link, blank, false)?;
        self.status.state = State::StartingFrlVideo(pipe);
        match self.frl_video_start(link, request, blank).await {
            Ok(running) => {
                self.status.frl_video_running = Some(running);
                self.status.state = State::FrlVideoRunning(pipe);
                Ok(running)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// The running stream as scanout and health checks see it.
    pub(in crate::amdgpu_dcn401_otg) fn frl_video_verify_running(
        &mut self,
        v: &FrlVideoRunning,
    ) -> Result<(), Error> {
        for (reg, mask, value) in [
            (CLOCK, 1, 1),
            (FIFO, 1, 1),
            (CONTROL, 1, 1),
            (SOURCE, 7, u32::from(v.request.pipe)),
        ] {
            if self.read(self.frl_at(reg))? & mask != value {
                return Err(Error::Readback(self.frl_at(reg)));
            }
        }
        if self.status.frl_link != Some(v.link) {
            return Err(Error::Invalid);
        }
        self.frl_link_witnesses(&v.link)?;
        self.frl_verify_format(v.timing.blank)?;
        let route = self.layout.base + STREAM_CLOCK * 4;
        if self.read(route)? & 15 != 8 | u32::from(v.request.pipe) {
            return Err(Error::Readback(route));
        }
        if let Some(a) = self.status.frl_audio {
            self.frl_audio_verify(v, &a)?;
        } else {
            self.frl_audio_quiet()?;
        }
        Ok(())
    }
    /// Linux's FRL link_set_dpms_off up to the link: AVMUTE, blank, the
    /// generic packets stopped, then the timing; the link stays active and
    /// the clock owner then stops HDMISTREAMCLK.
    pub(in crate::amdgpu_dcn401_otg) async fn stop_frl_video(
        &mut self,
        path: Path,
    ) -> Result<(), Error> {
        let v = self.status.frl_video_running.ok_or(Error::Invalid)?;
        let pipe = v.request.pipe;
        if self.status.state != State::FrlVideoRunning(pipe) || self.status.frl_audio.is_some() {
            return Err(Error::Busy);
        }
        if v.link.path != path {
            return Err(Error::Invalid);
        }
        self.frl_video_verify_running(&v)?;
        self.status.state = State::StoppingFrlVideo(pipe);
        let blank = v.timing.blank;
        let result = async {
            self.update(self.frl_at(GC_CONTROL), 1, 1)?;
            self.update(self.frl_at(FIFO), 1, 0)?;
            self.update(self.frl_at(CONTROL), 1, 0)?;
            self.update(self.frl_at(CLOCK), 1, 0)?;
            for reg in PACKETS {
                self.update(self.frl_at(reg), u32::MAX, 0)?;
            }
            self.disable(pipe).await?;
            self.restage_source(blank.timing.request)?;
            self.frl_video_verify(&v.link, blank, false)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.frl_video_running = None;
                self.status.state = State::FrlLinkActive(path.transmitter);
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
    /// Route HDMISTREAMCLK from `request.pipe` and start black RGB/4:2:0 video on
    /// the port's active FRL link.
    /// # Safety
    /// start_hdmi_video's obligations for the FRL link and the HPO FRL
    /// stream encoder, which no other display may use.
    pub(crate) async unsafe fn start_frl_video(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        path: Path,
        request: FrlVideoRequest,
    ) -> Result<FrlVideoRunning, Error> {
        if self.0.status.state != State::FrlLinkActive(path.transmitter) {
            return Err(Error::Busy);
        }
        let regs = self.0.io.0;
        let clock = dccg
            .retained_timing_clock(regs, clocks, request.pipe)
            .map_err(Error::PipeClocks)?;
        dccg.route_frl_stream(regs, clocks, request.pipe)
            .map_err(Error::PipeClocks)?;
        self.0.start_frl_video(path, request, clock).await
    }
    /// Stop the port's FRL video and HDMISTREAMCLK, keeping the link.
    /// # Safety
    /// As for `start_frl_video`; scanout stopped first.
    pub(crate) async unsafe fn stop_frl_video(
        &mut self,
        dccg: &mut dccg::Dccg,
        path: Path,
    ) -> Result<(), Error> {
        self.0.stop_frl_video(path).await?;
        dccg.unroute_frl_stream(self.0.io.0)
            .map_err(Error::PipeClocks)
    }
}
