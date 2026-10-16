//! Native DP 128b/132b SST video: the HPO stream encoder on a trained
//! 128b/132b link, as Linux's dcn401_enable_stream, update_sst_payload and
//! dcn31_hpo_dp_stream_enc_dp_unblank bring it up (RGB black from the
//! running timing; scanout is a separate owner), and the reverse.
//!
//! The DCCG half (DPSTREAMCLK from the pipe, SYMCLK32_SE from the PHY) is
//! the clock owner's; this owner requires and rechecks it.
use super::*;

// HPO DP stream encoder (stride 0xd4).
const SE_CLOCK: u64 = 0x3623;
const SE_INPUT_MUX: u64 = 0x3624;
const SE_RAMP: u64 = 0x3626;
const VPG_MEM_PWR: u64 = 0x3656;
const SYM32_CONTROL: u64 = 0x365d;
const VID_FIFO: u64 = 0x365e;
const MSA_DOUBLE_BUFFER: u64 = 0x365f;
const FORMAT_DOUBLE_BUFFER: u64 = 0x3660;
const PIXEL_FORMAT: u64 = 0x3661;
const MSA: u64 = 0x3662;
const HBLANK: u64 = 0x366b;
const GSP: [u64; 4] = [0x366c, 0x366e, 0x366f, 0x3671];
const SDP: u64 = 0x367b;
const VID_STREAM: u64 = 0x3685;
const VID_CRC: u64 = 0x3687;
// HPO DP link encoder (stride 0xd4).
const SAT_UPDATE: u64 = 0x36b8;
const VC_RATE: u64 = 0x36b9;
const SAT: u64 = 0x36bf;
// DCN bank 1 DCCG stream clocks, relative to SYMCLK32_LE_CNTL (0x66).
const DPSTREAMCLK_FROM_LE: u64 = (0x66 - 0x4a) * 4;
const SYMCLK32_SE_FROM_LE: u64 = 4;
const PAYLOAD_TABLE_STATUS: u32 = 0x2c0;
const PAYLOAD_ALLOCATE: u32 = 0x1c0;

/// One SST stream's share of a 128b/132b link, as Linux's
/// update_sst_payload computes it from the average time slots per MTP
/// (the stream's bandwidth with pixel-to-symbol padding over a 64th of
/// the link's): whole slots for the sink's payload table and the encoder's
/// allocation, the throttled VC rate (X.Y, Y in 1/2^25), and the minimum
/// blanking symbol width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhbrPayload {
    pub slots: u8,
    pub vc_rate: u32,
    pub hblank_symbols: u16,
}
/// Exact rational arithmetic where Linux uses 31.32 fixed point.
pub(in crate::amdgpu_dcn401_otg) fn uhbr_payload(
    t: &crate::amdgpu_dml::Timing,
    bpc: u32,
    settings: UhbrSettings,
) -> Option<UhbrPayload> {
    let pixel_khz = u128::from(t.pixel_clock_khz);
    let mut kbps = pixel_khz * u128::from(bpc) * 3;
    // apply_128b_132b_stream_overhead.
    let bits = u128::from(t.h_active) * u128::from(bpc) * 3;
    if bits != 0 {
        kbps = (kbps * bits.div_ceil(128) * 128).div_ceil(bits);
    }
    let link =
        u128::from(settings.rate.link_rate()) * 10_000 * u128::from(settings.lanes) / 10_000 * 9641;
    if link == 0 || pixel_khz == 0 {
        return None;
    }
    // avg = kbps / (link / 64).
    let (num, den) = (kbps * 64, link);
    let slots = num.div_ceil(den);
    if slots == 0 || slots > 64 {
        return None;
    }
    let mut x = num / den;
    let mut y = (num % den * (1 << 25)).div_ceil(den);
    if y == 1 << 25 {
        (x, y) = (x + 1, 0);
    }
    // h_blank / (128 bits / link x 64 slots) MTPs, times avg: the link
    // bandwidth cancels.
    let blank = u128::from(t.h_total - t.h_active);
    let hblank = blank * kbps * 64 / (pixel_khz * 128 * 64);
    Some(UhbrPayload {
        slots: slots as u8,
        vc_rate: (x as u32) << 25 | y as u32,
        hblank_symbols: u16::try_from(hblank).ok()?,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhbrVideoRunning {
    pub link: UhbrLinkTrained,
    /// HPO stream encoder.
    pub stream: u8,
    pub timing: BlankRunning,
    pub payload: UhbrPayload,
    /// The sink acknowledged the payload table and the allocation change.
    pub acknowledged: bool,
}
fn depth_bpc(depth: ColorDepth) -> u32 {
    match depth {
        ColorDepth::Bpc8 => 8,
        ColorDepth::Bpc10 => 10,
        ColorDepth::Bpc12 => 12,
    }
}
/// dcn31_hpo_dp_stream_enc_set_stream_attribute's whole-register values:
/// pixel format, then MSA0..8 (lane k in bits 8k+7:8k).
fn stream_attributes(blank: BlankApplied) -> [(u64, u32); 10] {
    let t = blank.timing.request.timing;
    let depth = depth_bpc(blank.request.depth);
    let (field, misc_depth) = match depth {
        8 => (1, 0x20),
        10 => (2, 0x40),
        _ => (3, 0x60),
    };
    let misc0 = misc_depth | u32::from(blank.request.limited) << 3;
    let freq = u64::from(t.pixel_clock_khz) * 1000;
    let f = |shift: u32| (freq >> shift & 0xff) as u32;
    let lanes = |b: [u32; 4]| b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
    let h_start = t.h_total - t.h_active - t.h_front_porch;
    let v_start = t.v_total - t.v_active - t.v_front_porch;
    let hsp = if t.h_sync_positive { 0 } else { 0x80 };
    let vsp = if t.v_sync_positive { 0 } else { 0x80 };
    [
        (PIXEL_FORMAT, field << 8),
        (MSA, lanes([0, 0, 0, f(40)])),
        (MSA + 1, lanes([0, 0, 0, f(32)])),
        (MSA + 2, lanes([0, 0, 0, f(24)])),
        (
            MSA + 3,
            lanes([t.h_total >> 8, h_start >> 8, t.h_active >> 8, f(16)]),
        ),
        (
            MSA + 4,
            lanes([t.h_total & 0xff, h_start & 0xff, t.h_active & 0xff, f(8)]),
        ),
        (
            MSA + 5,
            lanes([t.v_total >> 8, v_start >> 8, t.v_active >> 8, f(0)]),
        ),
        (
            MSA + 6,
            lanes([t.v_total & 0xff, v_start & 0xff, t.v_active & 0xff, misc0]),
        ),
        (
            MSA + 7,
            lanes([hsp | t.h_sync_width >> 8, vsp | t.v_sync_width >> 8, 0, 0]),
        ),
        (
            MSA + 8,
            lanes([t.h_sync_width & 0xff, t.v_sync_width & 0xff, 0, 0]),
        ),
    ]
}
impl<I: Io> Engine<I> {
    fn stream_mapper(&self, stream: u8) -> u64 {
        self.layout.mpc_base + (0xe56 + u64::from(stream)) * 4
    }
    /// The DCCG's stream clocks for `stream`: DPSTREAMCLK from `pipe`,
    /// SYMCLK32_SE from the link's PHY.
    fn uhbr_stream_clocks(&mut self, stream: u8, pipe: u8, phy: u8) -> Result<(), Error> {
        let l = self.layout;
        let shift = 4 * u32::from(stream);
        for (at, value) in [
            (l.link_clock - DPSTREAMCLK_FROM_LE, 8 | u32::from(pipe)),
            (l.link_clock - SYMCLK32_SE_FROM_LE, 8 | u32::from(phy)),
        ] {
            if self.read(at)? >> shift & 0xf != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// The link, its stream clocks, timing and the stream's own state.
    fn uhbr_video_verify(
        &mut self,
        link: &UhbrLinkTrained,
        stream: u8,
        blank: BlankApplied,
        running: bool,
    ) -> Result<(), Error> {
        let pipe = blank.request.pipe;
        self.uhbr_verify_owned(link, Some(stream), running.then_some(pipe))?;
        self.uhbr_stream_clocks(stream, pipe, link.path.transmitter)?;
        let plan = blank.timing.request.plan()?;
        self.verify_blank_source(blank, plan, running, true, false)
    }
    fn uhbr_write(&mut self, at: u64, value: u32) -> Result<(), Error> {
        self.update(at, u32::MAX, value)
    }
    /// update_sst_payload's DPCD half: the sink's VC payload table for VC 1
    /// from slot 0, then up to 150 ms for its table-updated flag. Linux
    /// carries on without it; whether it came is returned.
    async fn uhbr_payload_table(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        slots: u8,
    ) -> Result<bool, Error> {
        write(io, path, PAYLOAD_TABLE_STATUS, &mut [1]).await?;
        write(io, path, PAYLOAD_ALLOCATE, &mut [1]).await?;
        write(io, path, PAYLOAD_ALLOCATE + 1, &mut [0]).await?;
        write(io, path, PAYLOAD_ALLOCATE + 2, &mut [slots]).await?;
        for _ in 0..30 {
            if read::<1>(io, path, PAYLOAD_TABLE_STATUS).await?[0] & 1 != 0 {
                return Ok(true);
            }
            io.delay(5000).await;
        }
        Ok(false)
    }
    /// dcn31_hpo_dp_link_enc_update_stream_allocation_table with the ACT
    /// trigger, then poll_for_allocation_change_trigger: the link must stay
    /// trained (8b/10b-style CR, EQ, symbol lock and interlane alignment,
    /// as Linux checks it) while the sink handles ACT, for up to 150 ms.
    async fn uhbr_allocate(
        &mut self,
        io: &mut impl UhbrTransport,
        link: &UhbrLinkTrained,
        stream: u8,
        slots: u8,
    ) -> Result<bool, Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(link.link).at(l, r);
        self.uhbr_write(at(SAT), u32::from(stream) | u32::from(slots) << 8)?;
        for vc in 1..4 {
            self.uhbr_write(at(SAT + vc), 0)?;
        }
        self.access(|io| {
            let old = checked(io.read(at(SAT_UPDATE)))?;
            io.write(at(SAT_UPDATE), (old & !3) | 1);
            Ok(())
        })?;
        self.wait(at(0x36b5), 0x3_0000, 0, 20_000).await?;
        for _ in 0..30 {
            let status = read::<3>(io, link.path, 0x202).await?;
            let lanes = [status[0], status[1], status[2], 0, 0, 0];
            if !(0..link.settings.lanes).all(|l| lane_bits(lanes, l) & 7 == 7) || status[2] & 1 == 0
            {
                return Err(Error::DpTraining(DpTrainingError::LinkLost));
            }
            if read::<1>(io, link.path, PAYLOAD_TABLE_STATUS).await?[0] & 2 != 0 {
                return Ok(true);
            }
            io.delay(5000).await;
        }
        Ok(false)
    }
    /// dcn31_hpo_dp_link_enc_set_throttled_vcp_size: the stream's VC rate
    /// in the link encoder, then the rate update.
    async fn uhbr_vc_rate(&mut self, link: u8, stream: u8, rate: u32) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(link).at(l, r);
        self.uhbr_write(at(VC_RATE + u64::from(stream)), rate)?;
        self.wait(at(0x36b5), 0x1000, 0, 1000).await
    }
    /// dcn31_hpo_dp_stream_enc_enable_stream: clock, reset handshake, then
    /// the encoder generating idle.
    async fn uhbr_stream_enable(&mut self, stream: u8) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        self.update(at(SE_CLOCK), 1, 1)?;
        self.update(at(SYM32_CONTROL), 0x10, 0x10)?;
        self.wait(at(SYM32_CONTROL), 0x100, 0x100, 1000).await?;
        self.update(at(SYM32_CONTROL), 0x10, 0)?;
        self.wait(at(SYM32_CONTROL), 0x100, 0, 1000).await?;
        self.update(at(SYM32_CONTROL), 1, 1)
    }
    /// dcn31_hpo_dp_stream_enc_dp_unblank from OTG `pipe`.
    async fn uhbr_unblank(&mut self, stream: u8, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        self.update(at(SE_INPUT_MUX), 7, u32::from(pipe))?;
        self.update(at(VID_STREAM), 1, 1)?;
        for (reg, reset, done) in [(VID_FIFO, 0x10, 0x100), (SE_RAMP, 0x10, 0x10_0000)] {
            self.update(at(reg), reset, reset)?;
            self.wait(at(reg), done, done, 1000).await?;
            self.update(at(reg), reset, 0)?;
            self.wait(at(reg), done, 0, 1000).await?;
        }
        self.update(at(VID_CRC), 0x11, 0x11)?;
        self.update(at(VID_FIFO), 1, 1)?;
        self.update(at(SE_RAMP), 1, 1)
    }
    async fn uhbr_video_start(
        &mut self,
        io: &mut impl UhbrTransport,
        link: UhbrLinkTrained,
        stream: u8,
        blank: BlankApplied,
        payload: UhbrPayload,
    ) -> Result<UhbrVideoRunning, Error> {
        let pipe = blank.request.pipe;
        let timeout = blank.timeout_us()?;
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        // vpg31_poweron: only GSP memory found powered down is woken.
        if self.read(at(VPG_MEM_PWR))? & 0x100 != 0 {
            self.update(at(VPG_MEM_PWR), 0x11, 1)?;
        }
        // Stream attributes, single-buffered for a stream being enabled.
        self.update(at(MSA_DOUBLE_BUFFER), 1, 0)?;
        self.update(at(FORMAT_DOUBLE_BUFFER), 1, 0)?;
        for (reg, value) in stream_attributes(blank) {
            if reg == PIXEL_FORMAT {
                self.update(at(reg), 0x331, value)?;
            } else {
                self.uhbr_write(at(reg), value)?;
            }
        }
        self.uhbr_stream_enable(stream).await?;
        self.update(self.stream_mapper(stream), 7, u32::from(link.link))?;
        // update_dp_info_packets with no packet: GSPs off, SDP path on.
        for reg in GSP {
            self.update(at(reg), 1, 0)?;
        }
        self.update(at(SDP), 1, 1)?;
        self.uhbr_video_verify(&link, stream, blank, false)?;
        self.enable_blank(blank, timeout).await?;
        self.uhbr_video_verify(&link, stream, blank, true)?;
        let table = self
            .uhbr_payload_table(io, link.path, payload.slots)
            .await?;
        let act = self.uhbr_allocate(io, &link, stream, payload.slots).await?;
        self.uhbr_vc_rate(link.link, stream, payload.vc_rate)
            .await?;
        self.uhbr_write(at(HBLANK), u32::from(payload.hblank_symbols))?;
        self.uhbr_unblank(stream, pipe).await?;
        self.uhbr_video_verify(&link, stream, blank, true)?;
        let timing = self.wait_blank_frames(blank, timeout).await?;
        let running = UhbrVideoRunning {
            link,
            stream,
            timing,
            payload,
            acknowledged: table && act,
        };
        self.uhbr_video_verify_running(&running)?;
        Ok(running)
    }
    /// Start black RGB video on the trained 128b/132b link through HPO
    /// stream encoder `stream`, from the prepared timing of `pipe`, whose
    /// stream clocks the clock owner has routed.
    pub(in crate::amdgpu_dcn401_otg) async fn start_uhbr_video(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        stream: u8,
        pipe: u8,
        clock: dccg::Applied,
    ) -> Result<UhbrVideoRunning, Error> {
        let t = path.transmitter;
        if self.status.state != State::UhbrLinkTrained(t) || !io.ready() {
            return Err(Error::Busy);
        }
        let link = self.status.uhbr_link.ok_or(Error::Invalid)?;
        if link.path != path || stream >= 4 || pipe >= 4 {
            return Err(Error::Invalid);
        }
        let blank = self.status.blanks[usize::from(pipe)].ok_or(Error::Invalid)?;
        if self.blank_timing(blank.request, clock)? != blank.timing
            || blank.request.pipe != pipe
            || blank.timing.clock != clock
        {
            return Err(Error::Invalid);
        }
        let request = blank.timing.request;
        if request.signal != Signal::HpoDisplayPort || request.ycbcr420 {
            return Err(Error::Unsupported);
        }
        request.validate_clock(clock)?;
        let payload = uhbr_payload(
            &request.timing,
            depth_bpc(blank.request.depth),
            link.settings,
        )
        .ok_or(Error::Unsupported)?;
        // The stream encoder and its mapping start quiet: nothing but the
        // clocks routed for it.
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        for (reg, mask) in [
            (SE_CLOCK, 0x11111),
            (SYM32_CONTROL, 0x111),
            (VID_STREAM, 0x101),
            (VID_FIFO, 0x111),
            (SE_RAMP, 0x10_0011),
            (SDP, 1),
        ] {
            if self.read(at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        self.uhbr_audio_quiet(stream)?;
        self.uhbr_video_verify(&link, stream, blank, false)?;
        self.status.state = State::StartingUhbrVideo(stream);
        match self
            .uhbr_video_start(io, link, stream, blank, payload)
            .await
        {
            Ok(running) => {
                self.status.uhbr_video_running = Some(running);
                self.status.state = State::UhbrVideoRunning(stream);
                Ok(running)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// The running stream as scanout and health checks see it.
    pub(in crate::amdgpu_dcn401_otg) fn uhbr_video_verify_running(
        &mut self,
        v: &UhbrVideoRunning,
    ) -> Result<(), Error> {
        self.uhbr_video_verify_transport(v)?;
        if let Some(a) = self.status.uhbr_audio {
            self.uhbr_audio_verify(v, &a)
        } else {
            self.uhbr_audio_quiet(v.stream)
        }
    }
    /// Transport checks usable during APG reset, before audio is enabled.
    pub(in crate::amdgpu_dcn401_otg) fn uhbr_video_verify_transport(
        &mut self,
        v: &UhbrVideoRunning,
    ) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(v.stream).at(l, r);
        for (reg, mask, value) in [
            (SE_CLOCK, 1, 1),
            (SYM32_CONTROL, 1, 1),
            (VID_STREAM, 1, 1),
            (VID_FIFO, 1, 1),
            (SE_RAMP, 1, 1),
            (SE_INPUT_MUX, 7, u32::from(v.timing.blank.request.pipe)),
        ] {
            if self.read(at(reg))? & mask != value {
                return Err(Error::Readback(at(reg)));
            }
        }
        if self.read(self.stream_mapper(v.stream))? & 7 != u32::from(v.link.link) {
            return Err(Error::Readback(self.stream_mapper(v.stream)));
        }
        // Audio bandwidth is valid only for the retained format/timing and
        // native blank width. Recheck them before audio writes and after waits.
        for (reg, value) in stream_attributes(v.timing.blank) {
            let mask = if reg == PIXEL_FORMAT { 0x331 } else { u32::MAX };
            if self.read(at(reg))? & mask != value {
                return Err(Error::Readback(at(reg)));
            }
        }
        if self.read(at(HBLANK))? & 0xffff != u32::from(v.payload.hblank_symbols) {
            return Err(Error::Readback(at(HBLANK)));
        }
        let pipe = v.timing.blank.request.pipe;
        self.uhbr_verify_owned(&v.link, Some(v.stream), Some(pipe))?;
        self.uhbr_stream_clocks(v.stream, pipe, v.link.path.transmitter)
    }
    /// Linux's 128b/132b link_set_dpms_off up to the link: blank
    /// (dcn31_hpo_dp_stream_enc_dp_blank), the payload deallocated (VC rate
    /// and blanking width, the sink's table, the encoder's allocation with
    /// ACT), the stream encoder disabled, then the timing stopped. The link
    /// stays trained; the clock owner then parks the stream clocks.
    pub(in crate::amdgpu_dcn401_otg) async fn stop_uhbr_video(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
    ) -> Result<(), Error> {
        let v = self.status.uhbr_video_running.ok_or(Error::Invalid)?;
        if self.status.state != State::UhbrVideoRunning(v.stream)
            || self.status.uhbr_audio.is_some()
            || !io.ready()
        {
            return Err(Error::Busy);
        }
        if v.link.path != path {
            return Err(Error::Invalid);
        }
        self.uhbr_video_verify_running(&v)?;
        let stream = v.stream;
        let blank = v.timing.blank;
        let pipe = blank.request.pipe;
        self.status.state = State::StoppingUhbrVideo(stream);
        let result = async {
            let l = self.layout;
            let at = |r| DpStream::Hpo(stream).at(l, r);
            self.update(at(VID_STREAM), 1, 0)?;
            self.wait(at(VID_STREAM), 0x100, 0, 50_000).await?;
            self.update(at(SDP), 1, 0)?;
            self.update(at(VID_FIFO), 1, 0)?;
            self.update(at(SE_RAMP), 1, 0)?;
            self.uhbr_vc_rate(v.link.link, stream, 0).await?;
            self.uhbr_write(at(HBLANK), 0)?;
            self.uhbr_payload_table(io, path, 0).await?;
            self.uhbr_allocate(io, &v.link, stream, 0).await?;
            // dce110_disable_stream: packets off, then the encoder.
            for reg in GSP {
                self.update(at(reg), 1, 0)?;
            }
            self.update(at(SYM32_CONTROL), 1, 0)?;
            self.update(at(SE_CLOCK), 1, 0)?;
            self.disable(pipe).await?;
            // Restage the OPP route after master and busy are off, as DP
            // SST video stop does.
            self.update(
                self.layout.odm(pipe, SOURCE),
                0xf0000,
                u32::from(pipe) << 16,
            )?;
            self.uhbr_video_verify(&v.link, stream, blank, false)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.uhbr_video_running = None;
                self.status.state = State::UhbrLinkTrained(path.transmitter);
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
    /// Route HPO stream encoder `stream`'s clocks from `pipe` and start
    /// black RGB video on the port's trained 128b/132b link.
    /// # Safety
    /// start_dp_video's obligations for the 128b/132b link and HPO stream
    /// encoder `stream`, which no other display may use.
    pub(crate) async unsafe fn start_uhbr_video(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        io: &mut dmub::Dmub,
        path: Path,
        stream: u8,
        pipe: u8,
    ) -> Result<UhbrVideoRunning, Error> {
        if self.0.status.state != State::UhbrLinkTrained(path.transmitter) {
            return Err(Error::Busy);
        }
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        let regs = self.0.io.0;
        let clock = dccg
            .retained_timing_clock(regs, clocks, pipe)
            .map_err(Error::PipeClocks)?;
        dccg.route_hpo_stream(regs, clocks, stream, pipe, path.transmitter)
            .map_err(Error::PipeClocks)?;
        self.0.start_uhbr_video(io, path, stream, pipe, clock).await
    }
    /// Stop the port's 128b/132b video and park its stream clocks, leaving
    /// the link trained.
    /// # Safety
    /// As for `start_uhbr_video`; scanout stopped first.
    pub(crate) async unsafe fn stop_uhbr_video(
        &mut self,
        dccg: &mut dccg::Dccg,
        io: &mut dmub::Dmub,
        path: Path,
    ) -> Result<(), Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        let stream = self
            .0
            .status
            .uhbr_video_running
            .ok_or(Error::Invalid)?
            .stream;
        self.0.stop_uhbr_video(io, path).await?;
        dccg.unroute_hpo_stream(self.0.io.0, stream)
            .map_err(Error::PipeClocks)
    }
}
