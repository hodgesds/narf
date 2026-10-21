//! Native DCN401 HDMI FRL video: the single HPO FRL stream encoder (VPG4)
//! on a trained FRL link, as Linux brings it up: hpo_enc401_set_hdmi_
//! stream_attribute (pixel format, active/blank, borrow mode, packets per
//! line, general control, audio InfoFrame line), the AVI (and HDMI 1.4b
//! vendor) InfoFrame in VPG4 (hpo_enc401_update_hdmi_info_packets),
//! hpo_enc401_enable from the OTG, the timing running, hpo_enc401_unblank.
//! A compressed (DSC) timing is compressed between the stream attribute and
//! the InfoFrames, as link_set_dsc_on_stream runs after FRL training: the
//! pipe's DSC engines, hpo_enc401_hdmi_set_dsc_config (HDMI_DSC_MODE, the
//! FIFO's compressed format, the CVTEM PPS in generic packets 5-10) and the
//! OPTC's DSC mode; the stream attribute then zeroes the GCP depth.
//! RGB or YCbCr black until a scanout takes over. The HDMISTREAMCLK half is the
//! clock owner's; this owner requires and rechecks it. Stop is Linux's
//! AVMUTE, hpo_enc401_blank and hpo_enc401_stop_hdmi_info_packets; a DSC
//! stays until the timing retires (`stop_dsc`).
use super::*;
use crate::amdgpu_dcn401_otg::hdmi_link::{avi_infoframe_in, vendor_infoframe};
use crate::amdgpu_dcn_inventory::Path;
use crate::amdgpu_frl_cap::FrlBorrow;

const PIXEL_FORMAT: u64 = 0x8e0;
const PACKET_CONTROL: u64 = 0x8e1;
const VBI_PACKET_CONTROL1: u64 = 0x8e3;
const GC_CONTROL: u64 = 0x8e5;
const GENERIC_CONTROL0: u64 = 0x8e6;
const GENERIC_CONTROL1: u64 = 0x8e7;
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
    /// HDMI_BORROW_MODE: the capacity check's, or for a DSC stream the
    /// decided link's (update_borrow_mode_from_dsc_padding).
    pub borrow: FrlBorrow,
    /// HDMI_HC_ACTIVE/HDMI_HC_BLANK: the compressed check's tribyte
    /// targets; zero for an uncompressed stream.
    pub hc_active: u16,
    pub hc_blank: u16,
    pub avi: Avi,
    /// amdgpu_dm_fill_hdr_info_packet's DRM InfoFrame while
    /// HDR_OUTPUT_METADATA is set: generic packet 4
    /// (hpo_enc401_update_hdmi_info_packets' hdrsmd).
    pub hdr: Option<crate::amdgpu_hdr::InfoPacket>,
}

/// hpo_enc401_hdmi_set_dsc_config's CVTEM (HDMI 2.1 compressed video
/// transport EMP) for a PPS, as the generic packets it writes in order:
/// packet 5 (first, New), 6-9, 10 (last), then 5 again with New cleared.
/// Linux fills one packet buffer throughout, so later packets keep bytes the
/// earlier ones left (packet 10's from packet 9, the second packet 5's from
/// packet 10); this keeps them. With no DSC padding (enable_hblank_borrow
/// off) Hback is the timing's back porch and HCactive_bytes covers each
/// slice's ceil(slice width x bpp / 8).
pub(crate) fn cvtem_packets(
    t: &crate::amdgpu_dml::Timing,
    cfg: &crate::amdgpu_dsc::DscConfig,
    pps: &[u8; 128],
) -> [(u32, [u8; 36]); 7] {
    let slices = cfg.slices_h;
    let pic_width = t.h_active;
    let h_back = t.h_total - pic_width - t.h_sync_width - t.h_front_porch;
    let hc_bytes = slices * (pic_width / slices * cfg.bpp_x16).div_ceil(128);
    // [hb0, hb1, hb2, hb3, sb0..sb31].
    let mut p = [0u8; 36];
    let mut out = [(0, [0u8; 36]); 7];
    let sb = 4;
    p[0] = 0x7f;
    p[1] = 0x80;
    p[2] = 0;
    // Sync, VFR and New; Organization_ID 1 (VESA); Data_Set_Tag 2;
    // Data_Set_Length 136.
    p[sb] = 1 << 1 | 1 << 2 | 1 << 7;
    p[sb + 2] = 1;
    p[sb + 4] = 2;
    p[sb + 6] = 136;
    p[sb + 7..sb + 28].copy_from_slice(&pps[..21]);
    out[0] = (5, p);
    p[1] = 0;
    for i in 1..4 {
        p[2] = i as u8;
        p[sb..sb + 28].copy_from_slice(&pps[21 + 28 * (i - 1)..21 + 28 * i]);
        out[i] = (5 + i as u32, p);
    }
    p[2] = 4;
    p[sb..sb + 23].copy_from_slice(&pps[105..128]);
    p[sb + 23] = t.h_front_porch as u8;
    p[sb + 24] = (t.h_front_porch >> 8) as u8;
    p[sb + 25] = t.h_sync_width as u8;
    p[sb + 26] = (t.h_sync_width >> 8) as u8;
    p[sb + 27] = h_back as u8;
    out[4] = (9, p);
    p[1] = 1 << 6;
    p[2] = 5;
    p[sb] = (h_back >> 8) as u8;
    p[sb + 1] = hc_bytes as u8;
    p[sb + 2] = (hc_bytes >> 8) as u8;
    out[5] = (10, p);
    p[0] = 0x7f;
    p[1] = 0x80;
    p[2] = 0;
    p[sb] = 1 << 1 | 1 << 2;
    p[sb + 2] = 1;
    p[sb + 4] = 2;
    p[sb + 6] = 136;
    p[sb + 7..sb + 28].copy_from_slice(&pps[..21]);
    out[6] = (5, p);
    out
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
        if self.read(route)? & 15 != 8 | self.layout.inst_field(blank.request.pipe) {
            return Err(Error::Readback(route));
        }
        let plan = blank.timing.request.plan()?;
        self.verify_blank_source(blank, plan, running, true, false)
    }
    /// hpo_enc401_set_hdmi_stream_attribute and set_dsc_config(NULL):
    /// uncompressed RGB or 4:2:0. The DTO keeps the full pixel rate;
    /// subsampled active/blank widths count pixel pairs in the encoder. A
    /// compressed stream's GCP carries no depth.
    fn frl_format_registers(blank: BlankApplied) -> [(u64, u32, u32); 3] {
        let t = blank.timing.request.timing;
        let y420 = u32::from(blank.request.ycbcr420);
        let (depth, deep) = match blank.request.depth {
            _ if blank.timing.request.dsc.is_some() => (0, 0),
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
    /// hpo_enc401_hdmi_set_dsc_config's fields: the FIFO's pixel encoding
    /// type (compressed) and compressed format (4:4:4), and HDMI_DSC_MODE
    /// (OPTC_DSC_ENABLED_444); all zero uncompressed.
    fn frl_dsc_fields(blank: BlankApplied) -> [(u64, u32, u32); 2] {
        let dsc = blank.timing.request.dsc.is_some();
        [
            (FIFO, 0x10100, if dsc { 0x100 } else { 0 }),
            (PIXEL_FORMAT, 0x300_0000, if dsc { 1 << 24 } else { 0 }),
        ]
    }
    /// The stream attribute and DSC fields as the running stream has them,
    /// and for a DSC stream generic packets 5-10 sent every frame on line 2.
    fn frl_verify_format(&mut self, blank: BlankApplied) -> Result<(), Error> {
        let dsc = Self::frl_dsc_fields(blank);
        for (reg, mask, value) in Self::frl_format_registers(blank) {
            let (dsc_mask, dsc_value) = dsc
                .iter()
                .find(|d| d.0 == reg)
                .map_or((0, 0), |d| (d.1, d.2));
            let at = self.frl_at(reg);
            if self.read(at)? & mask != (value & !dsc_mask) | dsc_value {
                return Err(Error::Readback(at));
            }
        }
        self.frl_verify_dsc_packets(blank)
    }
    /// The DRM InfoFrame's generic packet 4 sent every frame on line 2.
    fn frl_verify_hdr(&mut self, request: &FrlVideoRequest) -> Result<(), Error> {
        if request.hdr.is_none() {
            return Ok(());
        }
        for (at, mask, value) in self.frl_packet_controls(4) {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// For a DSC stream, generic packets 5-10 sent every frame on line 2.
    fn frl_verify_dsc_packets(&mut self, blank: BlankApplied) -> Result<(), Error> {
        if blank.timing.request.dsc.is_some() {
            for index in 5..=10 {
                for (at, mask, value) in self.frl_packet_controls(index) {
                    if self.read(at)? & mask != value {
                        return Err(Error::Readback(at));
                    }
                }
            }
        }
        Ok(())
    }
    /// A generic packet's SEND/CONT pair and its line (2) register field.
    fn frl_packet_controls(&self, index: u32) -> [(u64, u32, u32); 2] {
        let control = if index < 8 {
            GENERIC_CONTROL0
        } else {
            GENERIC_CONTROL1
        };
        let send = 3 << (4 * (index % 8));
        let line = 16 * (index % 2);
        [
            (self.frl_at(control), send, send),
            (
                self.frl_at(GENERIC_LINE0_1 + u64::from(index / 2)),
                0x7fff << line,
                2 << line,
            ),
        ]
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
        self.update(self.frl_at(MODE), 3, request.borrow as u32)?;
        self.update(
            self.frl_at(PACKET_CONTROL),
            0x1f,
            u32::from(request.audio_packets_line),
        )?;
        self.update(
            self.frl_at(HC_ACTIVE_BLANK),
            u32::MAX,
            u32::from(request.hc_active) | u32::from(request.hc_blank) << 16,
        )?;
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
    /// vpg31_poweron.
    async fn frl_vpg_on(&mut self) -> Result<(), Error> {
        if self.read(self.frl_at(VPG_MEM_PWR))? & 0x100 != 0 {
            self.update(self.frl_at(VPG_MEM_PWR), 0x11, 1)?;
            self.wait(self.frl_at(VPG_MEM_PWR), 0x100, 0, 1000).await?;
        }
        Ok(())
    }
    /// hpo_enc401_update_hdmi_info_packet for a valid packet: VPG4's
    /// generic packet `index` written and latched immediately
    /// (vpg3_update_generic_info_packet), then sent every frame on line 2.
    async fn frl_vpg_packet(&mut self, index: u32, packet: &[u8; 36]) -> Result<(), Error> {
        let base = self.layout.mpc_base;
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
        for (at, mask, value) in self.frl_packet_controls(index) {
            self.update(at, mask, value)?;
        }
        Ok(())
    }
    /// vpg31_poweron, then the AVI InfoFrame in generic packet 0 and, for
    /// an HDMI VIC, the vendor InfoFrame in 1: each written at its index,
    /// latched immediately, sent every frame on line 2.
    async fn frl_infoframes(
        &mut self,
        request: FrlVideoRequest,
        blank: BlankApplied,
    ) -> Result<(), Error> {
        self.frl_vpg_on().await?;
        let t = blank.timing.request.timing;
        let avi = avi_infoframe_in(
            &t,
            request.avi,
            blank.request.colorspace,
            blank.request.ycbcr420,
        );
        let vendor = vendor_infoframe(&t, request.avi);
        let hdr = request.hdr.filter(|p| p.valid).map(|p| p.bytes());
        for (index, packet) in [(0u32, Some(avi)), (1, vendor), (4, hdr)] {
            if let Some(packet) = packet {
                self.frl_vpg_packet(index, &packet).await?;
            }
        }
        Ok(())
    }
    /// New HDR metadata on the running FRL stream (amdgpu_dm's
    /// hdr_static_metadata stream update): generic packet 4 rewritten and
    /// latched immediately. Only a stream already sending the DRM InfoFrame
    /// takes new contents; entering or leaving HDR is a modeset.
    pub(in crate::amdgpu_dcn401_otg) async fn frl_update_hdr(
        &mut self,
        packet: crate::amdgpu_hdr::InfoPacket,
    ) -> Result<(), Error> {
        let mut running = self.status.frl_video_running.ok_or(Error::Invalid)?;
        if running.request.hdr.is_none() || !packet.valid {
            return Err(Error::Invalid);
        }
        self.frl_vpg_packet(4, &packet.bytes()).await?;
        running.request.hdr = Some(packet);
        self.status.frl_video_running = Some(running);
        Ok(())
    }
    /// link_set_dsc_on_stream(true) for a compressed FRL timing, after
    /// training: each segment's DSC, hpo_enc401_hdmi_set_dsc_config (its
    /// fields, then the CVTEM PPS), then the OPTC's DSC mode. An earlier
    /// start's DSC on this stopped stream is turned off first.
    async fn frl_dsc_start(&mut self, blank: BlankApplied) -> Result<(), Error> {
        let request = blank.timing.request;
        let Some(cfg) = request.dsc else {
            return Ok(());
        };
        let plan = request.plan()?;
        if self.status.frl_dsc == Some(request.pipe) {
            for o in plan.opps() {
                self.stop_dsc(o).await?;
            }
        }
        self.start_dsc_engines(&request, &cfg).await?;
        self.status.frl_dsc = Some(request.pipe);
        for (reg, mask, value) in Self::frl_dsc_fields(blank) {
            self.update(self.frl_at(reg), mask, value)?;
        }
        let regs = crate::amdgpu_dcn401_otg::dsc_hw::dsc_registers(&request, &cfg)?;
        let pps = crate::amdgpu_dsc::pack_pps(&regs.pps);
        self.frl_vpg_on().await?;
        for (index, packet) in cvtem_packets(&request.timing, &cfg, &pps) {
            self.frl_vpg_packet(index, &packet).await?;
        }
        self.start_dsc_optc(&request, &cfg)
    }
    /// hpo_enc401_hdmi_set_dsc_config(NULL): the FIFO's compressed fields
    /// and HDMI_DSC_MODE off (the generic packets are stopped with the
    /// video).
    pub(in crate::amdgpu_dcn401_otg) fn frl_dsc_off(&mut self) -> Result<(), Error> {
        self.update(self.frl_at(FIFO), 0x10100, 0)?;
        self.update(self.frl_at(PIXEL_FORMAT), 0x300_0000, 0)
    }
    /// hpo_enc401_enable from pipe `pipe`'s OTG instance
    /// (HDMI_STREAM_ENC_INPUT_MUX_SOURCE_SEL = otg_inst).
    async fn frl_stream_enable(&mut self, pipe: u8) -> Result<(), Error> {
        self.update(self.frl_at(CLOCK), 1, 1)?;
        self.update(self.frl_at(CONTROL), 0x11, 0x10)?;
        self.wait(self.frl_at(CONTROL), 0x100, 0x100, 1000).await?;
        self.update(self.frl_at(CONTROL), 0x10, 0)?;
        self.update(self.frl_at(CRC), 3, 3)?;
        self.update(self.frl_at(DB), 0x1000, 0x1000)?;
        self.update(self.frl_at(SOURCE), 7, self.layout.inst_field(pipe))
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
        self.frl_dsc_start(blank).await?;
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
        if link.path != path
            || pipe >= self.layout.pool.count()
            || request.audio_packets_line > 0x1f
            || request.hc_active > 0x7fff
            || request.hc_blank > 0x7fff
        {
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
        // The native DSC compresses RGB at the stream's depth.
        if timing
            .dsc
            .is_some_and(|c| u32::from(c.bpc) != blank.request.depth.bpc())
        {
            return Err(Error::Unsupported);
        }
        // Tribyte targets and active borrowing belong to compressed streams.
        if timing.dsc.is_none()
            && (request.hc_active != 0
                || request.hc_blank != 0
                || request.borrow == FrlBorrow::FromActive)
        {
            return Err(Error::Invalid);
        }
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
            (SOURCE, 7, self.layout.inst_field(v.request.pipe)),
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
        self.frl_verify_hdr(&v.request)?;
        let route = self.layout.base + STREAM_CLOCK * 4;
        if self.read(route)? & 15 != 8 | self.layout.inst_field(v.request.pipe) {
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
