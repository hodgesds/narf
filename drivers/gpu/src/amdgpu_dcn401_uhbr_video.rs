//! Native DP 128b/132b SST video: the HPO stream encoder on a trained
//! 128b/132b link, as Linux's dcn401_enable_stream, update_sst_payload and
//! dcn31_hpo_dp_stream_enc_dp_unblank bring it up (RGB black from the
//! running timing; scanout is a separate owner), and the reverse. A DSC
//! stream (the pipe's DSC and OPTC already compress it, as
//! link_set_dsc_on_stream leaves an HPO stream) is marked compressed in its
//! pixel format, has the sink decode DSC and its PPS sent through the
//! stream's VPG, and its VC payload sized for the compressed bandwidth.
//!
//! The stream's info packets follow dcn31_hpo_dp_stream_enc_update_dp_info_packets:
//! a VSC SDP carrying colorimetry in VPG generic packet 0 (GSP0) and HDR
//! static metadata in packet 3 (GSP3), each written with an immediate
//! update, with MSA MISC1 bit 6 saying the VSC SDP carries colorimetry.
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
/// DP_SYM32_ENC_SDP_GSP_CONTROL11: the PPS SDP.
const GSP11: u64 = 0x3677;
const SDP: u64 = 0x367b;
/// DP_SYM32_ENC_VID_VBID_CONTROL.
const VBID: u64 = 0x3684;
// The stream's VPG (VPG n+5, sharing the stride).
const VPG_ACCESS: u64 = 0x3651;
const VPG_DATA: u64 = 0x3652;
const VPG_IMMEDIATE: u64 = 0x3654;
const VPG_STATUS: u64 = 0x3655;
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
/// DP_DSC_ENABLE.
const DSC_ENABLE: u32 = 0x160;

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
/// dc_bandwidth_in_kbps_from_timing for 128b/132b RGB at `bpc`, with
/// apply_128b_132b_stream_overhead's pixel-to-symbol padding.
fn stream_kbps(t: &crate::amdgpu_dml::Timing, bpc: u32) -> u128 {
    let mut kbps = u128::from(t.pixel_clock_khz) * u128::from(bpc) * 3;
    let bits = u128::from(t.h_active) * u128::from(bpc) * 3;
    if bits != 0 {
        kbps = (kbps * bits.div_ceil(128) * 128).div_ceil(bits);
    }
    kbps
}
/// dc_bandwidth_in_kbps_from_timing for a DSC stream:
/// dc_dsc_stream_bandwidth_in_kbps (compressed bpp plus the slice
/// overhead), without 128b/132b padding.
fn dsc_stream_kbps(t: &crate::amdgpu_dml::Timing, cfg: &crate::amdgpu_dsc::DscConfig) -> u128 {
    let dsc = crate::amdgpu_dcn401_otg::dsc_hw::dsc_timing(t);
    u128::from(crate::amdgpu_dsc::dsc_kbps(&dsc, cfg.bpp_x16, cfg.slices_h))
}
/// dp_link_bandwidth_kbps for 128b/132b.
fn link_kbps(settings: UhbrSettings) -> u128 {
    u128::from(settings.rate.link_rate()) * 10_000 * u128::from(settings.lanes) / 10_000 * 9641
}
/// Exact rational arithmetic where Linux uses 31.32 fixed point.
pub(in crate::amdgpu_dcn401_otg) fn uhbr_payload(
    t: &crate::amdgpu_dml::Timing,
    bpc: u32,
    settings: UhbrSettings,
) -> Option<UhbrPayload> {
    payload_for(t, stream_kbps(t, bpc), settings)
}
/// update_sst_payload for a compressed stream: the same allocation, VC
/// rate and blanking width from the DSC stream's bandwidth.
pub(in crate::amdgpu_dcn401_otg) fn uhbr_dsc_payload(
    t: &crate::amdgpu_dml::Timing,
    cfg: &crate::amdgpu_dsc::DscConfig,
    settings: UhbrSettings,
) -> Option<UhbrPayload> {
    payload_for(t, dsc_stream_kbps(t, cfg), settings)
}
fn payload_for(
    t: &crate::amdgpu_dml::Timing,
    kbps: u128,
    settings: UhbrSettings,
) -> Option<UhbrPayload> {
    let pixel_khz = u128::from(t.pixel_clock_khz);
    let link = link_kbps(settings);
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
/// An MST stream's source rate on a 128b/132b link, as Linux's
/// allocate_mst_payload programs it in 31.32 fixed point: average time
/// slots per MTP as the stream's PBN (get_pbn_from_timing, with the
/// 128b/132b padding) over the link's PBN per slot (get_pbn_per_slot),
/// split into the HPO VC rate X.Y with Y in 1/2^25
/// (dcn31_hpo_dp_link_enc_set_throttled_vcp_size), and the minimum
/// blanking symbol width at that rate (set_hpo_dp_hblank_min_symbol_width).
/// Returns the VC_RATE register value (X in bits 31:25) and the width.
pub fn uhbr_mst_rate(
    t: &crate::amdgpu_dml::Timing,
    bpc: u32,
    settings: UhbrSettings,
) -> Option<(u32, u16)> {
    mst_rate_for(t, stream_kbps(t, bpc), settings)
}
/// `uhbr_mst_rate` for a DSC stream: its PBN from the compressed bandwidth
/// (dc_dsc_stream_bandwidth_in_kbps, no 128b/132b padding).
pub fn uhbr_mst_dsc_rate(
    t: &crate::amdgpu_dml::Timing,
    cfg: &crate::amdgpu_dsc::DscConfig,
    settings: UhbrSettings,
) -> Option<(u32, u16)> {
    mst_rate_for(t, dsc_stream_kbps(t, cfg), settings)
}
fn mst_rate_for(
    t: &crate::amdgpu_dml::Timing,
    kbps: u128,
    settings: UhbrSettings,
) -> Option<(u32, u16)> {
    use crate::amdgpu_dsc::Fixed;
    let link = i64::try_from(link_kbps(settings)).ok()?;
    let per_slot = Fixed::int(i32::try_from(link / 8000).ok()?).div_int(54);
    if per_slot.0 == 0 || t.pixel_clock_khz == 0 || link == 0 {
        return None;
    }
    let pbn = Fixed::fraction(i64::try_from(kbps * 64).ok()?, 54 * 8 * 1000);
    let avg = pbn.div(per_slot);
    let mut x = u32::try_from(avg.floor()).ok()?;
    let mut y = Fixed(avg.sub_int(x as i32).0 << 25).ceil() as u32;
    if y >> 25 != 0 {
        (x, y) = (x + 1, 0);
    }
    if x > 64 {
        return None;
    }
    let blank = Fixed::int(i32::try_from(t.h_total.checked_sub(t.h_active)?).ok()?)
        .div(Fixed::fraction(i64::from(t.pixel_clock_khz) * 10, 10));
    let slot = Fixed::fraction(32 * 4, link);
    let mtps = blank.div(slot.mul_int(64));
    let hblank = u16::try_from(mtps.mul(avg).floor()).ok()?;
    Some((x << 25 | y, hblank))
}
/// The info packets a 128b/132b stream sends, as resource_build_info_frame
/// gives them for a DP signal: the VSC SDP when the sink takes colorimetry
/// in it (use_vsc_sdp_for_colorimetry; mod_build_vsc_infopacket from the
/// stream's color space and depth) and amdgpu_dm's HDR metadata SDP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UhbrSdp {
    pub vsc_colorimetry: bool,
    pub hdr: Option<crate::amdgpu_hdr::InfoPacket>,
}
impl UhbrSdp {
    /// mod_build_vsc_infopacket for the stream's blank format (RGB).
    fn vsc(&self, blank: BlankApplied) -> Option<crate::amdgpu_hdr::InfoPacket> {
        crate::amdgpu_hdr::vsc_sdp(
            self.vsc_colorimetry,
            blank.request.colorspace,
            crate::amdgpu_hdr::PixelEncoding::Rgb,
            depth_bpc(blank.request.depth) as u8,
            false,
        )
    }
    /// GSP0 (VSC), GSP2 (SPD), GSP3 (HDR) and GSP5 (adaptive sync)
    /// continuous transmission as update_dp_info_packets sets them.
    fn enables(&self, blank: BlankApplied) -> [u32; 4] {
        [
            u32::from(self.vsc(blank).is_some()),
            0,
            u32::from(self.hdr.is_some()),
            0,
        ]
    }
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
    /// The VSC/HDR SDPs the stream sends.
    pub sdp: UhbrSdp,
}
fn depth_bpc(depth: ColorDepth) -> u32 {
    match depth {
        ColorDepth::Bpc8 => 8,
        ColorDepth::Bpc10 => 10,
        ColorDepth::Bpc12 => 12,
    }
}
/// dcn31_hpo_dp_stream_enc_set_stream_attribute's whole-register values:
/// pixel format, then MSA0..8 (lane k in bits 8k+7:8k), MISC1 saying
/// whether the VSC SDP carries colorimetry.
fn stream_attributes(blank: BlankApplied, vsc: bool) -> [(u64, u32); 10] {
    let t = blank.timing.request.timing;
    let depth = depth_bpc(blank.request.depth);
    let (field, misc_depth) = match depth {
        8 => (1, 0x20),
        10 => (2, 0x40),
        _ => (3, 0x60),
    };
    // The HPO encoder's MISC0/MISC1 for the output color space.
    let (misc0, misc1) = crate::amdgpu_hdr::hpo_msa_misc(
        blank.request.colorspace,
        crate::amdgpu_hdr::PixelEncoding::Rgb,
        depth as u8,
        vsc,
    );
    debug_assert_eq!(misc0 & 0xe0, misc_depth);
    // PIXEL_ENCODING_TYPE: compressed for a DSC stream.
    let compressed = u32::from(blank.timing.request.dsc.is_some());
    let freq = u64::from(t.pixel_clock_khz) * 1000;
    let f = |shift: u32| (freq >> shift & 0xff) as u32;
    let lanes = |b: [u32; 4]| b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
    let h_start = t.h_total - t.h_active - t.h_front_porch;
    let v_start = t.v_total - t.v_active - t.v_front_porch;
    let hsp = if t.h_sync_positive { 0 } else { 0x80 };
    let vsp = if t.v_sync_positive { 0 } else { 0x80 };
    [
        (PIXEL_FORMAT, field << 8 | compressed),
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
            lanes([
                hsp | t.h_sync_width >> 8,
                vsp | t.v_sync_width >> 8,
                0,
                misc1,
            ]),
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
        self.uhbr_sat_update(
            link.link,
            [u32::from(stream) | u32::from(slots) << 8, 0, 0, 0],
        )
        .await?;
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
    /// dcn31_hpo_dp_link_enc_update_stream_allocation_table: VC payload
    /// rows 0..3 (stream source, slot count), then SAT_UPDATE 1 (update
    /// with ACT) and the wait for it to leave pending.
    async fn uhbr_sat_update(&mut self, link: u8, rows: [u32; 4]) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(link).at(l, r);
        for (vc, row) in (0..).zip(rows) {
            self.uhbr_write(at(SAT + vc), row)?;
        }
        self.access(|io| {
            let old = checked(io.read(at(SAT_UPDATE)))?;
            io.write(at(SAT_UPDATE), (old & !3) | 1);
            Ok(())
        })?;
        self.wait(at(0x36b5), 0x3_0000, 0, 20_000).await
    }
    /// dcn31_hpo_dp_link_enc_set_throttled_vcp_size: the stream's VC rate
    /// in the link encoder, then the rate update.
    async fn uhbr_vc_rate(&mut self, link: u8, stream: u8, rate: u32) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(link).at(l, r);
        self.uhbr_write(at(VC_RATE + u64::from(stream)), rate)?;
        self.wait(at(0x36b5), 0x1000, 0, 1000).await
    }
    /// vpg3_update_generic_info_packet(index, packet, immediate) on HPO
    /// stream encoder `stream`'s VPG.
    async fn uhbr_packet(
        &mut self,
        stream: u8,
        index: u32,
        packet: crate::amdgpu_hdr::InfoPacket,
    ) -> Result<(), Error> {
        let l = self.layout;
        let at = move |r| DpStream::Hpo(stream).at(l, r);
        self.wait(at(VPG_STATUS), 2, 0, 500).await?;
        self.access(|io| {
            // CONFLICT_CLR and the data port are commands, not state.
            let status = checked(io.read(at(VPG_STATUS)))?;
            io.write(at(VPG_STATUS), status | 0x10);
            let access = checked(io.read(at(VPG_ACCESS)))?;
            io.write(at(VPG_ACCESS), (access & !0xff) | (index * 9));
            for word in packet.words() {
                io.write(at(VPG_DATA), word);
            }
            let immediate = checked(io.read(at(VPG_IMMEDIATE)))?;
            io.write(at(VPG_IMMEDIATE), immediate | 1 << index);
            Ok(())
        })
    }
    /// dcn31_hpo_dp_stream_enc_update_dp_info_packets: the VSC SDP in
    /// packet 0 and the HDR SDP in packet 3 (each with an immediate update),
    /// then GSP0/GSP2/GSP3/GSP5 continuous transmission for exactly the
    /// valid ones and the secondary data path on.
    async fn uhbr_infopackets(
        &mut self,
        stream: u8,
        blank: BlankApplied,
        sdp: UhbrSdp,
    ) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        if let Some(vsc) = sdp.vsc(blank) {
            self.uhbr_packet(stream, 0, vsc).await?;
        }
        if let Some(hdr) = sdp.hdr {
            self.uhbr_packet(stream, 3, hdr).await?;
        }
        for (reg, on) in GSP.into_iter().zip(sdp.enables(blank)) {
            self.update(at(reg), 1, on)?;
        }
        self.update(at(SDP), 1, 1)
    }
    /// The info packets' transmission enables as `sdp` sets them.
    fn uhbr_infopackets_verify(
        &mut self,
        stream: u8,
        blank: BlankApplied,
        sdp: UhbrSdp,
    ) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        for (reg, on) in GSP.into_iter().zip(sdp.enables(blank)) {
            if self.read(at(reg))? & 1 != on {
                return Err(Error::Readback(at(reg)));
            }
        }
        Ok(())
    }
    /// New HDR metadata on the running 128b/132b stream (amdgpu_dm's
    /// hdr_static_metadata stream update): packet 3 rewritten with an
    /// immediate update. Only a stream already sending the HDR SDP takes
    /// new contents; entering or leaving HDR is a modeset.
    pub(in crate::amdgpu_dcn401_otg) async fn uhbr_update_hdr(
        &mut self,
        packet: crate::amdgpu_hdr::InfoPacket,
    ) -> Result<(), Error> {
        let mut running = self.status.uhbr_video_running.ok_or(Error::Invalid)?;
        if running.sdp.hdr.is_none() || !packet.valid {
            return Err(Error::Invalid);
        }
        self.uhbr_packet(running.stream, 3, packet).await?;
        running.sdp.hdr = Some(packet);
        self.status.uhbr_video_running = Some(running);
        Ok(())
    }
    /// dcn31_hpo_dp_stream_enc_set_dsc_pps_info_packet(true, immediate):
    /// GSP11 in 128-byte mode (payload size 3), the packed PPS in the
    /// stream VPG's generic packets 11-14 (type 0x10, 127 bytes) as
    /// vpg3_update_generic_info_packet writes them and latched immediately,
    /// GSP11 on line 2 with VBID[6] on line 3 (SOF reference 0), then GSP11
    /// and the secondary data path on.
    async fn uhbr_pps(&mut self, stream: u8, request: &Request) -> Result<(), Error> {
        let Some(cfg) = request.dsc else {
            return Ok(());
        };
        let regs = crate::amdgpu_dcn401_otg::dsc_hw::dsc_registers(request, &cfg)?;
        let pps = crate::amdgpu_dsc::pack_pps(&regs.pps);
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        self.update(at(GSP11), 0x60, 3 << 5)?;
        for (i, chunk) in pps.chunks_exact(32).enumerate() {
            let index = 11 + i as u32;
            self.wait(at(VPG_STATUS), 2, 0, 500).await?;
            self.access(|io| {
                // CONFLICT_CLR and the data port are commands, not state.
                let status = checked(io.read(at(VPG_STATUS)))?;
                io.write(at(VPG_STATUS), status | 0x10);
                let access = checked(io.read(at(VPG_ACCESS)))?;
                io.write(at(VPG_ACCESS), (access & !0xff) | (index * 9));
                io.write(at(VPG_DATA), u32::from_le_bytes([0, 0x10, 127, 0]));
                for word in chunk.chunks_exact(4) {
                    io.write(
                        at(VPG_DATA),
                        u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
                    );
                }
                let immediate = checked(io.read(at(VPG_IMMEDIATE)))?;
                io.write(at(VPG_IMMEDIATE), immediate | 1 << index);
                Ok(())
            })?;
        }
        self.update(at(GSP11), 0xffff_0000, 2 << 16)?;
        self.update(at(VBID), 0xffff_0001, 3 << 16)?;
        self.update(at(GSP11), 1, 1)?;
        self.update(at(SDP), 1, 1)
    }
    /// The sink decodes DSC (dp_set_dsc_on_rx, read back), then the PPS:
    /// link_set_dpms_on's order after enable_stream.
    async fn uhbr_dsc_start(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        stream: u8,
        request: &Request,
    ) -> Result<(), Error> {
        if request.dsc.is_none() {
            return Ok(());
        }
        write(io, path, DSC_ENABLE, &mut [1]).await?;
        if read::<1>(io, path, DSC_ENABLE).await?[0] & 1 != 1 {
            return Err(sink_readback(DSC_ENABLE));
        }
        self.uhbr_pps(stream, request).await
    }
    /// A running DSC stream's PPS SDP: GSP11 sending 128 bytes on line 2,
    /// VBID[6] on line 3, the secondary data path on.
    fn uhbr_pps_verify(&mut self, stream: u8, request: &Request) -> Result<(), Error> {
        if request.dsc.is_none() {
            return Ok(());
        }
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        for (reg, mask, value) in [
            (GSP11, 0xffff_0061, 2 << 16 | 3 << 5 | 1),
            (VBID, 0xffff_0001, 3 << 16),
            (SDP, 1, 1),
        ] {
            if self.read(at(reg))? & mask != value {
                return Err(Error::Readback(at(reg)));
            }
        }
        Ok(())
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
    /// dcn401_enable_stream up to the payload: stream attributes, the
    /// encoder enabled and mapped to the link, packets, then the timing
    /// started blank (OTG black, the stream not yet unblanked).
    async fn uhbr_stream_prepare(
        &mut self,
        link: &UhbrLinkTrained,
        stream: u8,
        blank: BlankApplied,
        timeout: u64,
        sdp: UhbrSdp,
    ) -> Result<BlankRunning, Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        // vpg31_poweron: only GSP memory found powered down is woken.
        if self.read(at(VPG_MEM_PWR))? & 0x100 != 0 {
            self.update(at(VPG_MEM_PWR), 0x11, 1)?;
        }
        // Stream attributes, single-buffered for a stream being enabled.
        self.update(at(MSA_DOUBLE_BUFFER), 1, 0)?;
        self.update(at(FORMAT_DOUBLE_BUFFER), 1, 0)?;
        for (reg, value) in stream_attributes(blank, sdp.vsc_colorimetry) {
            if reg == PIXEL_FORMAT {
                self.update(at(reg), 0x331, value)?;
            } else {
                self.uhbr_write(at(reg), value)?;
            }
        }
        self.uhbr_stream_enable(stream).await?;
        self.update(self.stream_mapper(stream), 7, u32::from(link.link))?;
        // dcn401_enable_stream's update_info_frame: the VSC/HDR SDPs (or
        // none: GSPs off), SDP path on.
        self.uhbr_infopackets(stream, blank, sdp).await?;
        self.uhbr_video_verify(link, stream, blank, false)?;
        let timing = self.enable_blank(blank, timeout).await?;
        self.uhbr_video_verify(link, stream, blank, true)?;
        Ok(timing)
    }
    /// The unblank and the frames that prove the stream runs.
    async fn uhbr_stream_unblank(
        &mut self,
        mut running: UhbrVideoRunning,
        timeout: u64,
    ) -> Result<UhbrVideoRunning, Error> {
        let blank = running.timing.blank;
        self.uhbr_unblank(running.stream, blank.request.pipe)
            .await?;
        self.uhbr_video_verify(&running.link, running.stream, blank, true)?;
        running.timing = self.wait_blank_frames(blank, timeout).await?;
        self.uhbr_video_verify_running(&running)?;
        Ok(running)
    }
    async fn uhbr_video_start(
        &mut self,
        io: &mut impl UhbrTransport,
        link: UhbrLinkTrained,
        stream: u8,
        blank: BlankApplied,
        payload: UhbrPayload,
        sdp: UhbrSdp,
    ) -> Result<UhbrVideoRunning, Error> {
        let timeout = blank.timeout_us()?;
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        let timing = self
            .uhbr_stream_prepare(&link, stream, blank, timeout, sdp)
            .await?;
        self.uhbr_dsc_start(io, link.path, stream, &blank.timing.request)
            .await?;
        self.uhbr_video_verify(&link, stream, blank, true)?;
        let table = self
            .uhbr_payload_table(io, link.path, payload.slots)
            .await?;
        let act = self.uhbr_allocate(io, &link, stream, payload.slots).await?;
        self.uhbr_vc_rate(link.link, stream, payload.vc_rate)
            .await?;
        self.uhbr_write(at(HBLANK), u32::from(payload.hblank_symbols))?;
        let running = UhbrVideoRunning {
            link,
            stream,
            timing,
            payload,
            acknowledged: table && act,
            sdp,
        };
        self.uhbr_stream_unblank(running, timeout).await
    }
    /// The trained (or attached MST) link and prepared blank timing a new
    /// stream on HPO stream encoder `stream` starts from, its encoder and
    /// mapping quiet but for the clocks routed for it.
    fn uhbr_video_request(
        &mut self,
        path: Path,
        stream: u8,
        pipe: u8,
        clock: dccg::Applied,
        mst: bool,
    ) -> Result<(UhbrLinkTrained, BlankApplied), Error> {
        let t = path.transmitter;
        if self.status.state != State::UhbrLinkTrained(t) {
            return Err(Error::Busy);
        }
        let link = self.status.uhbr_link.ok_or(Error::Invalid)?;
        if link.path != path || stream >= 4 || pipe >= 4 || link.settings.mst != mst {
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
        let l = self.layout;
        let at = |r| DpStream::Hpo(stream).at(l, r);
        for (reg, mask) in [
            (SE_CLOCK, 0x11111),
            (SYM32_CONTROL, 0x111),
            (VID_STREAM, 0x101),
            (VID_FIFO, 0x111),
            (SE_RAMP, 0x10_0011),
            (SDP, 1),
            (GSP11, 1),
        ] {
            if self.read(at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        // No other payload names this encoder on the link.
        if (0..4).any(|vc| {
            self.read(DpStream::Hpo(link.link).at(l, SAT + vc))
                .is_ok_and(|row| row & 0x7f00 != 0 && row & 7 == u32::from(stream))
        }) {
            return Err(Error::Busy);
        }
        self.uhbr_audio_quiet(stream)?;
        self.uhbr_video_verify(&link, stream, blank, false)?;
        Ok((link, blank))
    }
    /// Start black RGB video on the trained 128b/132b link through HPO
    /// stream encoder `stream`, from the prepared timing of `pipe`, whose
    /// stream clocks the clock owner has routed.
    #[cfg(feature = "kernel-test")]
    pub(in crate::amdgpu_dcn401_otg) async fn start_uhbr_video(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        stream: u8,
        pipe: u8,
        clock: dccg::Applied,
    ) -> Result<UhbrVideoRunning, Error> {
        self.start_uhbr_video_with(io, path, stream, pipe, clock, UhbrSdp::default())
            .await
    }
    /// `start_uhbr_video` sending the VSC/HDR SDPs `sdp` asks for.
    pub(in crate::amdgpu_dcn401_otg) async fn start_uhbr_video_with(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        stream: u8,
        pipe: u8,
        clock: dccg::Applied,
        sdp: UhbrSdp,
    ) -> Result<UhbrVideoRunning, Error> {
        if !io.ready() {
            return Err(Error::Busy);
        }
        let (link, blank) = self.uhbr_video_request(path, stream, pipe, clock, false)?;
        let request = blank.timing.request;
        let payload = match request.dsc {
            Some(cfg) => uhbr_dsc_payload(&request.timing, &cfg, link.settings),
            None => uhbr_payload(
                &request.timing,
                depth_bpc(blank.request.depth),
                link.settings,
            ),
        }
        .ok_or(Error::Unsupported)?;
        self.status.state = State::StartingUhbrVideo(stream);
        match self
            .uhbr_video_start(io, link, stream, blank, payload, sdp)
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
    /// The first half of an MST stream on the selected display's 128b/132b
    /// MST link (trained or attached): the stream encoder enabled and
    /// mapped, its timing started blank, ready for the MST manager to add
    /// its `slots` payload (`update_uhbr_mst_allocation`,
    /// `set_uhbr_mst_vc_rate`) before `start_uhbr_mst_video` unblanks it.
    #[cfg(feature = "kernel-test")]
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_uhbr_mst_stream(
        &mut self,
        path: Path,
        stream: u8,
        pipe: u8,
        clock: dccg::Applied,
        slots: u8,
    ) -> Result<UhbrVideoRunning, Error> {
        self.prepare_uhbr_mst_stream_with(path, stream, pipe, clock, slots, UhbrSdp::default())
            .await
    }
    /// `prepare_uhbr_mst_stream` sending the VSC/HDR SDPs `sdp` asks for.
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_uhbr_mst_stream_with(
        &mut self,
        path: Path,
        stream: u8,
        pipe: u8,
        clock: dccg::Applied,
        slots: u8,
        sdp: UhbrSdp,
    ) -> Result<UhbrVideoRunning, Error> {
        let (link, blank) = self.uhbr_video_request(path, stream, pipe, clock, true)?;
        let request = blank.timing.request;
        let (vc_rate, hblank_symbols) = match request.dsc {
            Some(cfg) => uhbr_mst_dsc_rate(&request.timing, &cfg, link.settings),
            None => uhbr_mst_rate(
                &request.timing,
                depth_bpc(blank.request.depth),
                link.settings,
            ),
        }
        .ok_or(Error::Unsupported)?;
        if !(1..=64).contains(&slots) || vc_rate >> 25 > u32::from(slots) {
            return Err(Error::Invalid);
        }
        let timeout = blank.timeout_us()?;
        self.status.state = State::StartingUhbrVideo(stream);
        let result = async {
            let timing = self
                .uhbr_stream_prepare(&link, stream, blank, timeout, sdp)
                .await?;
            let ready = UhbrVideoRunning {
                link,
                stream,
                timing,
                payload: UhbrPayload {
                    slots,
                    vc_rate,
                    hblank_symbols,
                },
                acknowledged: false,
                sdp,
            };
            self.uhbr_stream_verify_ready(&ready)?;
            Ok(ready)
        }
        .await;
        match result {
            Ok(ready) => {
                self.status.uhbr_video_running = Some(ready);
                self.status.state = State::UhbrStreamReady(stream);
                Ok(ready)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// The selected display's prepared MST stream, its payload added (the
    /// VC rate and blanking width set as recorded), unblanked.
    pub(in crate::amdgpu_dcn401_otg) async fn start_uhbr_mst_video(
        &mut self,
        path: Path,
    ) -> Result<UhbrVideoRunning, Error> {
        let v = self.status.uhbr_video_running.ok_or(Error::Invalid)?;
        if self.status.state != State::UhbrStreamReady(v.stream) {
            return Err(Error::Busy);
        }
        if v.link.path != path {
            return Err(Error::Invalid);
        }
        self.uhbr_stream_verify_ready(&v)?;
        let l = self.layout;
        let at = |r| DpStream::Hpo(v.link.link).at(l, r);
        if self.read(at(VC_RATE + u64::from(v.stream)))? != v.payload.vc_rate {
            return Err(Error::Readback(at(VC_RATE + u64::from(v.stream))));
        }
        let timeout = v.timing.blank.timeout_us()?;
        self.status.state = State::StartingUhbrVideo(v.stream);
        let running = UhbrVideoRunning {
            acknowledged: true,
            ..v
        };
        // A compressed stream's PPS SDP (its decoder was enabled through the
        // MST manager before the payload), then the unblank.
        let request = v.timing.blank.timing.request;
        let started = async {
            self.uhbr_pps(v.stream, &request).await?;
            self.uhbr_stream_unblank(running, timeout).await
        };
        match started.await {
            Ok(running) => {
                self.status.uhbr_video_running = Some(running);
                self.status.state = State::UhbrVideoRunning(v.stream);
                Ok(running)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// A prepared (or blanked) MST stream: encoder enabled and mapped, the
    /// video, FIFO and ramp off, the timing running blank.
    fn uhbr_stream_verify_ready(&mut self, v: &UhbrVideoRunning) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(v.stream).at(l, r);
        for (reg, mask, value) in [
            (SE_CLOCK, 1, 1),
            (SYM32_CONTROL, 1, 1),
            (VID_STREAM, 0x101, 0),
            (VID_FIFO, 1, 0),
            (SE_RAMP, 1, 0),
            (SDP, 1, 1),
        ] {
            if self.read(at(reg))? & mask != value {
                return Err(Error::Readback(at(reg)));
            }
        }
        if self.read(self.stream_mapper(v.stream))? & 7 != u32::from(v.link.link) {
            return Err(Error::Readback(self.stream_mapper(v.stream)));
        }
        for (reg, value) in stream_attributes(v.timing.blank, v.sdp.vsc_colorimetry) {
            let mask = if reg == PIXEL_FORMAT { 0x331 } else { u32::MAX };
            if self.read(at(reg))? & mask != value {
                return Err(Error::Readback(at(reg)));
            }
        }
        self.uhbr_infopackets_verify(v.stream, v.timing.blank, v.sdp)?;
        self.uhbr_audio_quiet(v.stream)?;
        self.uhbr_video_verify(&v.link, v.stream, v.timing.blank, true)
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
        for (reg, value) in stream_attributes(v.timing.blank, v.sdp.vsc_colorimetry) {
            let mask = if reg == PIXEL_FORMAT { 0x331 } else { u32::MAX };
            if self.read(at(reg))? & mask != value {
                return Err(Error::Readback(at(reg)));
            }
        }
        self.uhbr_infopackets_verify(v.stream, v.timing.blank, v.sdp)?;
        if self.read(at(HBLANK))? & 0xffff != u32::from(v.payload.hblank_symbols) {
            return Err(Error::Readback(at(HBLANK)));
        }
        self.uhbr_pps_verify(v.stream, &v.timing.blank.timing.request)?;
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
        if v.link.path != path || v.link.settings.mst {
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
            // link_set_dsc_enable(false) after the stream: the sink stops
            // decoding (unchecked, as Linux ignores it), then the PPS SDP
            // (dp_set_dsc_pps_info_packet(false): GSP11 off, payload size
            // 0). The DSC and OPTC keep compressing for a restart; retiring
            // the timing turns them off.
            if blank.timing.request.dsc.is_some() {
                let _ = write(io, path, DSC_ENABLE, &mut [0]).await;
                self.update(at(GSP11), 0x61, 0)?;
            }
            self.disable(pipe).await?;
            // Restage the OPP route after master and busy are off, as DP
            // SST video stop does.
            self.restage_source(blank.timing.request)?;
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
    /// Linux's 128b/132b MST link_set_dpms_off up to the payload: the
    /// selected display's running stream blanked
    /// (dcn31_hpo_dp_stream_enc_dp_blank), its encoder still enabled and
    /// its timing running, for the MST manager to remove its payload.
    pub(in crate::amdgpu_dcn401_otg) async fn blank_uhbr_mst_video(
        &mut self,
        path: Path,
    ) -> Result<(), Error> {
        let v = self.status.uhbr_video_running.ok_or(Error::Invalid)?;
        if self.status.state != State::UhbrVideoRunning(v.stream)
            || self.status.uhbr_audio.is_some()
        {
            return Err(Error::Busy);
        }
        if v.link.path != path || !v.link.settings.mst {
            return Err(Error::Invalid);
        }
        self.uhbr_video_verify_running(&v)?;
        self.status.state = State::StoppingUhbrVideo(v.stream);
        let result = async {
            let l = self.layout;
            let at = |r| DpStream::Hpo(v.stream).at(l, r);
            self.update(at(VID_STREAM), 1, 0)?;
            self.wait(at(VID_STREAM), 0x100, 0, 50_000).await?;
            self.update(at(VID_FIFO), 1, 0)?;
            self.update(at(SE_RAMP), 1, 0)?;
            self.uhbr_stream_verify_ready(&v)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.state = State::UhbrStreamReady(v.stream);
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// After the MST manager removed the blanked stream's payload (its VC
    /// rate and blanking width zero, no allocation row naming it): packets
    /// and the encoder off (dce110_disable_stream), then the timing
    /// stopped. The link stays up for the other streams.
    pub(in crate::amdgpu_dcn401_otg) async fn stop_uhbr_mst_stream(
        &mut self,
        path: Path,
    ) -> Result<(), Error> {
        let v = self.status.uhbr_video_running.ok_or(Error::Invalid)?;
        if self.status.state != State::UhbrStreamReady(v.stream) {
            return Err(Error::Busy);
        }
        if v.link.path != path || !v.link.settings.mst {
            return Err(Error::Invalid);
        }
        self.uhbr_stream_verify_ready(&v)?;
        let l = self.layout;
        let at = |r| DpStream::Hpo(v.stream).at(l, r);
        let link_at = |r| DpStream::Hpo(v.link.link).at(l, r);
        if self.read(link_at(VC_RATE + u64::from(v.stream)))? != 0
            || self.read(at(HBLANK))? & 0xffff != 0
        {
            return Err(Error::Busy);
        }
        for vc in 0..4 {
            let row = self.read(link_at(SAT + vc))?;
            if row & 0x7f00 != 0 && row & 7 == u32::from(v.stream) {
                return Err(Error::Busy);
            }
        }
        let blank = v.timing.blank;
        self.status.state = State::StoppingUhbrVideo(v.stream);
        let result = async {
            self.update(at(SDP), 1, 0)?;
            for reg in GSP {
                self.update(at(reg), 1, 0)?;
            }
            // dp_set_dsc_pps_info_packet(false): GSP11 off, payload size 0.
            if blank.timing.request.dsc.is_some() {
                self.update(at(GSP11), 0x61, 0)?;
            }
            self.update(at(SYM32_CONTROL), 1, 0)?;
            self.update(at(SE_CLOCK), 1, 0)?;
            self.disable(blank.request.pipe).await?;
            self.restage_source(blank.timing.request)?;
            self.uhbr_video_verify(&v.link, v.stream, blank, false)
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
    /// The selected display's blanked stream on its 128b/132b MST link on
    /// `transmitter`: payloads change only around a stream that is
    /// prepared but not yet unblanked, or blanked to stop.
    fn uhbr_mst_stream(&mut self, transmitter: u8) -> Result<UhbrVideoRunning, Error> {
        let v = self.status.uhbr_video_running.ok_or(Error::Invalid)?;
        if self.status.state != State::UhbrStreamReady(v.stream)
            || self.status.uhbr_link != Some(v.link)
        {
            return Err(Error::Busy);
        }
        if v.link.path.transmitter != transmitter || !v.link.settings.mst {
            return Err(Error::Invalid);
        }
        self.uhbr_stream_verify_ready(&v)?;
        Ok(v)
    }
    /// dcn31_hpo_dp_link_enc_update_stream_allocation_table for the MST
    /// link: the payloads in start-slot order, the rest cleared, with ACT.
    pub(in crate::amdgpu_dcn401_otg) async fn update_uhbr_mst_allocation(
        &mut self,
        transmitter: u8,
        table: &[MstAllocation],
    ) -> Result<(), Error> {
        let link = self.uhbr_mst_stream(transmitter)?.link;
        let total: u32 = table.iter().map(|a| u32::from(a.slots)).sum();
        if table.len() > 4 || total > 64 || table.iter().any(|a| a.stream >= 4 || a.slots > 64) {
            return Err(Error::Invalid);
        }
        let mut rows = [0; 4];
        for (row, a) in rows.iter_mut().zip(table) {
            *row = u32::from(a.stream) | u32::from(a.slots) << 8;
        }
        self.uhbr_sat_update(link.link, rows).await
    }
    /// The selected display's stream rate on its MST link: the recorded VC
    /// rate (`rate` X.Y, Y in 1/2^25) then the blanking width, or both
    /// zero as its payload goes.
    pub(in crate::amdgpu_dcn401_otg) async fn set_uhbr_mst_vc_rate(
        &mut self,
        transmitter: u8,
        stream: u8,
        (x, y): (u32, u32),
    ) -> Result<(), Error> {
        let v = self.uhbr_mst_stream(transmitter)?;
        if v.stream != stream || y >> 25 != 0 || x > 64 {
            return Err(Error::Invalid);
        }
        let rate = x << 25 | y;
        let hblank = match rate {
            0 => 0,
            r if r == v.payload.vc_rate => v.payload.hblank_symbols,
            _ => return Err(Error::Invalid),
        };
        self.uhbr_vc_rate(v.link.link, stream, rate).await?;
        let at = |r| DpStream::Hpo(stream).at(self.layout, r);
        self.uhbr_write(at(HBLANK), u32::from(hblank))
    }
}
impl Otg {
    /// Route HPO stream encoder `stream`'s clocks from `pipe` and start
    /// black RGB video on the port's trained 128b/132b link.
    /// # Safety
    /// start_dp_video's obligations for the 128b/132b link and HPO stream
    /// encoder `stream`, which no other display may use.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async unsafe fn start_uhbr_video(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        io: &mut dmub::Dmub,
        path: Path,
        stream: u8,
        pipe: u8,
        sdp: UhbrSdp,
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
        self.0
            .start_uhbr_video_with(io, path, stream, pipe, clock, sdp)
            .await
    }
    /// Route HPO stream encoder `stream`'s clocks from `pipe` and prepare
    /// its MST stream on the selected display's 128b/132b MST link, blank,
    /// for a payload of `slots`.
    /// # Safety
    /// As for `start_uhbr_video`; the MST manager owns the link's payloads.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async unsafe fn prepare_uhbr_mst_stream(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        path: Path,
        stream: u8,
        pipe: u8,
        slots: u8,
        sdp: UhbrSdp,
    ) -> Result<UhbrVideoRunning, Error> {
        if self.0.status.state != State::UhbrLinkTrained(path.transmitter) {
            return Err(Error::Busy);
        }
        let regs = self.0.io.0;
        let clock = dccg
            .retained_timing_clock(regs, clocks, pipe)
            .map_err(Error::PipeClocks)?;
        dccg.route_hpo_stream(regs, clocks, stream, pipe, path.transmitter)
            .map_err(Error::PipeClocks)?;
        self.0
            .prepare_uhbr_mst_stream_with(path, stream, pipe, clock, slots, sdp)
            .await
    }
    /// Unblank the selected display's prepared MST stream, its payload
    /// added.
    /// # Safety
    /// As for `prepare_uhbr_mst_stream`.
    pub(crate) async unsafe fn start_uhbr_mst_video(
        &mut self,
        path: Path,
    ) -> Result<UhbrVideoRunning, Error> {
        self.0.start_uhbr_mst_video(path).await
    }
    /// Blank the selected display's running MST stream for its payload's
    /// removal.
    /// # Safety
    /// As for `stop_uhbr_video`.
    pub(crate) async unsafe fn blank_uhbr_mst_video(&mut self, path: Path) -> Result<(), Error> {
        self.0.blank_uhbr_mst_video(path).await
    }
    /// Stop the selected display's blanked MST stream, its payload removed,
    /// and park its stream clocks.
    /// # Safety
    /// As for `stop_uhbr_video`.
    pub(crate) async unsafe fn stop_uhbr_mst_stream(
        &mut self,
        dccg: &mut dccg::Dccg,
        path: Path,
    ) -> Result<(), Error> {
        let stream = self
            .0
            .status
            .uhbr_video_running
            .ok_or(Error::Invalid)?
            .stream;
        self.0.stop_uhbr_mst_stream(path).await?;
        dccg.unroute_hpo_stream(self.0.io.0, stream)
            .map_err(Error::PipeClocks)
    }
    /// Program the selected display's 128b/132b MST link's VC payload
    /// table and trigger ACT.
    /// # Safety
    /// As for `update_mst_allocation`.
    pub(crate) async unsafe fn update_uhbr_mst_allocation(
        &mut self,
        transmitter: u8,
        table: &[MstAllocation],
    ) -> Result<(), Error> {
        self.0.update_uhbr_mst_allocation(transmitter, table).await
    }
    /// Set the selected display's MST stream rate on its 128b/132b link.
    /// # Safety
    /// As for `update_mst_allocation`.
    pub(crate) async unsafe fn set_uhbr_mst_vc_rate(
        &mut self,
        transmitter: u8,
        stream: u8,
        rate: (u32, u32),
    ) -> Result<(), Error> {
        self.0.set_uhbr_mst_vc_rate(transmitter, stream, rate).await
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
