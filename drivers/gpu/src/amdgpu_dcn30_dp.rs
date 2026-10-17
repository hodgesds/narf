//! Navi22 DCN3.0 DisplayPort SST over the DIO: the link-encoder (DIG
//! backend/DP PHY logic) and stream-encoder (DIG frontend, MSA, SDPs) halves
//! Linux drives around the VBIOS transmitter table and native AUX.
//!
//! Sequences follow `dcn10_link_encoder.c` (`enc1_configure_encoder`,
//! `dcn10_link_encoder_set_dp_phy_pattern_training_pattern`,
//! `set_dp_phy_pattern_passthrough_mode`, `setup_panel_mode`,
//! `link_encoder_disable`), `dcn10_stream_encoder.c`
//! (`enc1_stream_encoder_dp_set_stream_attribute`,
//! `enc1_stream_encoder_stop_dp_info_packets`, `enc1_stream_encoder_dp_blank`),
//! `dcn20_stream_encoder.c` (`enc2_stream_encoder_dp_set_stream_attribute`,
//! `enc2_stream_encoder_dp_unblank`), `dcn30_dio_stream_encoder.c`
//! (`enc3_stream_encoder_update_dp_info_packets`) and `dcn30_vpg.c`. Offsets
//! and masks are `dcn_3_0_0_offset.h`/`_sh_mask.h` at DCN base index 2; the
//! DIG, DP and VPG blocks stride 0x100. Link registers are indexed by the
//! transmitter, stream registers by the DIG frontend.
//!
//! Scope: 8b/10b SST, RGB, 6/8/10 bpc, no MST/DSC/FEC/PSR. The link policy
//! (capabilities, LTTPR modes, training, fallback, link loss) lives in
//! `amdgpu_dcn30_dp_link`, driving [`DioSource`].
use crate::{
    amdgpu_dcn30_dp_link as link_layer,
    amdgpu_dcn30_takeover::Regs,
    amdgpu_dml::Timing,
    amdgpu_navi22_modeset::{DpLink, Error},
};
use core::future::Future;

const STRIDE: u64 = 0x100;
// VPG (per frontend).
const VPG_GENERIC_PACKET_ACCESS_CTRL: u64 = 0x2068;
const VPG_GENERIC_PACKET_DATA: u64 = 0x2069;
const VPG_GSP_IMMEDIATE_UPDATE_CTRL: u64 = 0x206b;
const VPG_GENERIC_STATUS: u64 = 0x206c;
const VPG_GENERIC_CONFLICT_OCCURED: u32 = 1 << 1;
const VPG_GENERIC_CONFLICT_CLR: u32 = 1 << 4;
// DIG frontend.
const DIG_FE_CNTL: u64 = 0x208b;
const DIG_START: u32 = 1 << 10;
// DIG backend / DP link (per transmitter).
const DIG_BE_EN_CNTL: u64 = 0x20b1;
const DIG_ENABLE: u32 = 1 << 0;
const DP_LINK_CNTL: u64 = 0x2108;
const DP_LINK_TRAINING_COMPLETE: u32 = 1 << 4;
const DP_CONFIG: u64 = 0x210b;
const DP_DPHY_INTERNAL_CTRL: u64 = 0x210f;
const DP_LINK_FRAMING_CNTL: u64 = 0x2113;
const DP_IDLE_BS_INTERVAL: u32 = 0x0003_ffff;
const DP_VBID_DISABLE: u32 = 1 << 24;
const DP_VID_ENHANCED_FRAME_MODE: u32 = 1 << 28;
const DP_DPHY_CNTL: u64 = 0x2117;
const DPHY_BYPASS: u32 = 1 << 16;
const DP_DPHY_TRAINING_PATTERN_SEL: u64 = 0x2118;
const DP_DPHY_PRBS_CNTL: u64 = 0x211d;
const DPHY_PRBS_EN: u32 = 1 << 0;
const DP_DPHY_SCRAM_CNTL: u64 = 0x211e;
const DPHY_SCRAMBLER_ADVANCE: u32 = 1 << 4;
const DPHY_SCRAMBLER_BS_COUNT: u32 = 0x0003_ff00;
// DP stream (per frontend).
const DP_PIXEL_FORMAT: u64 = 0x2109;
const DP_PIXEL_ENCODING: u32 = 0x0000_0007;
const DP_COMPONENT_DEPTH: u32 = 0x0700_0000;
const DP_PIXEL_COMBINE: u32 = 0x3000_0000;
const DP_MSA_COLORIMETRY: u64 = 0x210a;
const DP_VID_STREAM_CNTL: u64 = 0x210c;
const DP_VID_STREAM_ENABLE: u32 = 1 << 0;
const DP_VID_STREAM_DIS_DEFER: u32 = 0x0000_0300;
const DP_VID_STREAM_STATUS: u32 = 1 << 16;
const DP_STEER_FIFO: u64 = 0x210d;
const DP_STEER_FIFO_RESET: u32 = 1 << 0;
const DP_MSA_MISC: u64 = 0x210e;
const DP_VID_TIMING: u64 = 0x2110;
const DP_VID_M_N_GEN_EN: u32 = 1 << 8;
const DP_VID_N_MUL: u32 = 0x0000_0c00;
const DP_VID_N: u64 = 0x2111;
const DP_VID_M: u64 = 0x2112;
const DP_SEC_CNTL: u64 = 0x212b;
const DP_SEC_STREAM_ENABLE: u32 = 1 << 0;
const DP_SEC_GSP0_ENABLE: u32 = 1 << 20;
const DP_SEC_FRAMING4: u64 = 0x2130;
const DP_SST_SDP_SPLITTING: u32 = 1 << 0;
const DP_MSA_TIMING_PARAM1: u64 = 0x214c;
const DP_MSA_TIMING_PARAM2: u64 = 0x214d;
const DP_MSA_TIMING_PARAM3: u64 = 0x214e;
const DP_MSA_TIMING_PARAM4: u64 = 0x214f;
/// The highest dword this module touches, for the bank bound.
pub(crate) const LAST_REG: u32 = (DP_MSA_TIMING_PARAM4 + 5 * STRIDE) as u32;
/// `enc2_stream_encoder_dp_unblank`'s fixed N.
const N_VID: u64 = 0x8000;
/// `LINK_RATE_REF_FREQ_IN_KHZ`.
pub const LINK_RATE_REF_KHZ: u32 = 27_000;
/// DPCD addresses this module's callers use.
pub const DPCD_SET_POWER: u32 = 0x600;
pub const DPCD_DPRX_FEATURE_ENUMERATION_LIST: u32 = 0x2210;
/// `DP_SET_POWER_D3` (`dp_disable_link_phy` → `dpcd_write_rx_power_ctrl`).
pub const SET_POWER_D3: u8 = 2;

async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}

/// Native AUX to one sink, as the training and stream code need it.
pub trait Aux {
    fn read(
        &mut self,
        address: u32,
        data: &mut [u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;
    fn write(
        &mut self,
        address: u32,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;
    /// One HDMI SCDC register read over the connector's DDC (I2C 0x54,
    /// `link_query_ddc_data`); see `amdgpu_dcn30_hdmi::write_scdc_data`. A
    /// channel with no SCDC (DP AUX, no sink) fails; a sink that declared
    /// no SCDC is never asked.
    fn scdc_read(&mut self, offset: u8) -> impl Future<Output = Result<u8, Error>> + Send {
        let _ = offset;
        core::future::ready(Err(Error::Hdmi(crate::amdgpu_dcn30_hdmi::Error::Scdc)))
    }
    /// One HDMI SCDC register write (`[offset, value]` to I2C 0x54).
    fn scdc_write(
        &mut self,
        offset: u8,
        value: u8,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        let _ = (offset, value);
        core::future::ready(Err(Error::Hdmi(crate::amdgpu_dcn30_hdmi::Error::Scdc)))
    }
    /// `dce_aux_configure_timeout` on this connector's AUX engine (the
    /// LTTPR or default reply timeout, in microseconds).
    fn set_timeout_us(&mut self, _us: u32) -> impl Future<Output = Result<(), Error>> + Send {
        async { Ok(()) }
    }
    /// Whether a sink is still connected (debounced HPD): Linux's
    /// `link->type != dc_connection_none`.
    fn connected(&mut self) -> impl Future<Output = bool> + Send {
        async { true }
    }
    /// The waits between transactions the link layer prescribes.
    fn delay_us(&mut self, us: u64) -> impl Future<Output = ()> + Send {
        sleep_us(us)
    }
}

/// Bits per component on a DP RGB stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    Bpc6,
    Bpc8,
    Bpc10,
}
impl Depth {
    /// `DP_COMPONENT_PIXEL_DEPTH_*`, which is also MSA MISC0's bpc code.
    fn code(self) -> u32 {
        match self {
            Depth::Bpc6 => 0,
            Depth::Bpc8 => 1,
            Depth::Bpc10 => 2,
        }
    }
    pub fn bits_per_pixel(self) -> u8 {
        match self {
            Depth::Bpc6 => 18,
            Depth::Bpc8 => 24,
            Depth::Bpc10 => 30,
        }
    }
}

/// `mod_build_vsc_infopacket` revision 5 (`use_vsc_sdp_for_colorimetry`):
/// HB 00 07 05 13; DB16 = pixel encoding << 4 | colorimetry (RGB, sRGB: 0),
/// DB17 = bpc code (full range), DB18 = content type 0. Laid out as the
/// 36-byte HB0..3 + SB0..31 packet the VPG takes.
pub fn vsc_packet(depth: Depth) -> [u8; 36] {
    let mut p = [0u8; 36];
    p[..4].copy_from_slice(&[0x00, 0x07, 0x05, 0x13]);
    p[4 + 17] = depth.code() as u8;
    p
}

/// `enc1_stream_encoder_dp_blank` on frontend `fe` of the DCN bank at `dcn2`.
pub(crate) async fn blank_stream(regs: &mut Regs, dcn2: u64, fe: u8) -> Result<(), Error> {
    let reg = |r: u64| dcn2 + (r + u64::from(fe) * STRIDE) * 4;
    if regs.read(reg(DP_VID_STREAM_CNTL))? & DP_VID_STREAM_ENABLE == 0 {
        return Ok(());
    }
    // Disable at the start of the next vertical blank.
    regs.update(reg(DP_VID_STREAM_CNTL), DP_VID_STREAM_DIS_DEFER, 2 << 8)?;
    regs.update(reg(DP_VID_STREAM_CNTL), DP_VID_STREAM_ENABLE, 0)?;
    // DP_BLANK_MAX_RETRY * 501 polls 10 us apart; Linux logs a timeout.
    regs.wait(
        reg(DP_VID_STREAM_CNTL),
        DP_VID_STREAM_STATUS,
        0,
        10,
        20 * 501,
    )
    .await?;
    // Only after the stream stopped, or STATUS can stick at 1.
    regs.update(reg(DP_STEER_FIFO), DP_STEER_FIFO_RESET, DP_STEER_FIFO_RESET)
}

/// The DP half of one DIG backend.
#[derive(Clone, Copy, Debug)]
pub struct Link {
    regs: Regs,
    dcn2: u64,
    transmitter: u8,
}
impl Link {
    pub(crate) fn new(regs: Regs, dcn2: u64, transmitter: u8) -> Result<Self, Error> {
        if transmitter >= 6 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            regs,
            dcn2,
            transmitter,
        })
    }
    fn reg(&self, r: u64) -> u64 {
        self.dcn2 + (r + u64::from(self.transmitter) * STRIDE) * 4
    }
    fn update(&mut self, r: u64, mask: u32, value: u32) -> Result<(), Error> {
        let reg = self.reg(r);
        self.regs.update(reg, mask, value)
    }
    fn write(&mut self, r: u64, value: u32) -> Result<(), Error> {
        let reg = self.reg(r);
        self.regs.write(reg, value)
    }
    /// `dcn10_is_dig_enabled`.
    pub fn enabled(&mut self) -> Result<bool, Error> {
        let reg = self.reg(DIG_BE_EN_CNTL);
        Ok(self.regs.read(reg)? & DIG_ENABLE != 0)
    }
    /// `enc1_configure_encoder`: the lane count (`DP_UDI_LANES`, written
    /// whole) and the scrambler advance.
    pub fn configure(&mut self, lanes: u8) -> Result<(), Error> {
        if !matches!(lanes, 1 | 2 | 4) {
            return Err(Error::Invalid);
        }
        self.write(DP_CONFIG, u32::from(lanes - 1))?;
        self.update(
            DP_DPHY_SCRAM_CNTL,
            DPHY_SCRAMBLER_ADVANCE,
            DPHY_SCRAMBLER_ADVANCE,
        )
    }
    /// `dcn10_link_encoder_set_dp_phy_pattern_training_pattern`: TPS1..4 as
    /// index 0..3.
    pub fn training_pattern(&mut self, index: u8) -> Result<(), Error> {
        if index > 3 {
            return Err(Error::Invalid);
        }
        self.write(DP_DPHY_TRAINING_PATTERN_SEL, u32::from(index))?;
        self.update(DP_LINK_CNTL, DP_LINK_TRAINING_COMPLETE, 0)?;
        self.update(DP_DPHY_CNTL, DPHY_BYPASS, 0)?;
        self.update(DP_DPHY_PRBS_CNTL, DPHY_PRBS_EN, 0)
    }
    /// `set_dp_phy_pattern_passthrough_mode(DP_PANEL_MODE_DEFAULT)`: video
    /// idle, enhanced framing, training complete.
    pub fn passthrough(&mut self) -> Result<(), Error> {
        self.write(DP_DPHY_INTERNAL_CTRL, 0)?;
        self.update(
            DP_LINK_FRAMING_CNTL,
            DP_IDLE_BS_INTERVAL | DP_VBID_DISABLE | DP_VID_ENHANCED_FRAME_MODE,
            0x2000 | DP_VID_ENHANCED_FRAME_MODE,
        )?;
        self.update(DP_DPHY_SCRAM_CNTL, DPHY_SCRAMBLER_BS_COUNT, 0x1ff << 8)?;
        self.update(
            DP_LINK_CNTL,
            DP_LINK_TRAINING_COMPLETE,
            DP_LINK_TRAINING_COMPLETE,
        )?;
        self.update(DP_DPHY_CNTL, DPHY_BYPASS, 0)?;
        self.update(DP_DPHY_PRBS_CNTL, DPHY_PRBS_EN, 0)
    }
    /// `link_encoder_disable` after the VBIOS DISABLE: TPS1, training not
    /// complete, default panel mode.
    pub fn reset(&mut self) -> Result<(), Error> {
        self.write(DP_DPHY_TRAINING_PATTERN_SEL, 0)?;
        self.update(DP_LINK_CNTL, DP_LINK_TRAINING_COMPLETE, 0)?;
        self.write(DP_DPHY_INTERNAL_CTRL, 0)
    }
}

/// The DP half of one DIG frontend (stream encoder).
#[derive(Clone, Copy, Debug)]
pub struct Stream {
    regs: Regs,
    dcn2: u64,
    fe: u8,
}
impl Stream {
    pub(crate) fn new(regs: Regs, dcn2: u64, fe: u8) -> Result<Self, Error> {
        if fe >= 6 {
            return Err(Error::Invalid);
        }
        Ok(Self { regs, dcn2, fe })
    }
    fn reg(&self, r: u64) -> u64 {
        self.dcn2 + (r + u64::from(self.fe) * STRIDE) * 4
    }
    fn update(&mut self, r: u64, mask: u32, value: u32) -> Result<(), Error> {
        let reg = self.reg(r);
        self.regs.update(reg, mask, value)
    }
    fn write(&mut self, r: u64, value: u32) -> Result<(), Error> {
        let reg = self.reg(r);
        self.regs.write(reg, value)
    }
    fn read(&mut self, r: u64) -> Result<u32, Error> {
        let reg = self.reg(r);
        self.regs.read(reg)
    }
    /// `enc2_stream_encoder_dp_set_stream_attribute` for RGB full-range sRGB,
    /// progressive, no borders: pixel format, MSA MISC0/1 and timing, then
    /// SST SDP splitting per the sink's DPRX feature.
    pub fn set_stream_attribute(
        &mut self,
        timing: &Timing,
        depth: Depth,
        vsc_colorimetry: bool,
        sdp_split: bool,
    ) -> Result<(), Error> {
        let h_blank = timing
            .h_total
            .checked_sub(timing.h_active)
            .ok_or(Error::Invalid)?;
        let h_back_porch = h_blank
            .checked_sub(timing.h_front_porch)
            .and_then(|v| v.checked_sub(timing.h_sync_width))
            .ok_or(Error::Invalid)?;
        let h_start = timing.h_sync_width + h_back_porch;
        let v_start = timing
            .v_total
            .checked_sub(timing.v_active)
            .and_then(|v| v.checked_sub(timing.v_front_porch))
            .ok_or(Error::Invalid)?;
        for value in [timing.h_total, timing.v_total, h_start, v_start] {
            if value == 0 || value > 0xffff {
                return Err(Error::Invalid);
            }
        }
        if timing.h_sync_width > 0x7fff || timing.v_sync_width > 0x7fff {
            return Err(Error::Invalid);
        }
        self.update(
            DP_PIXEL_FORMAT,
            DP_PIXEL_ENCODING | DP_COMPONENT_DEPTH,
            depth.code() << DP_COMPONENT_DEPTH.trailing_zeros(),
        )?;
        // MISC1 bit 6: colorimetry from the VSC SDP; bit 7 clear for sRGB.
        let misc1 = self.read(DP_MSA_MISC)? & !0xc0 | if vsc_colorimetry { 0x40 } else { 0 };
        // MISC0: bpc in bits 7:5; RGB full range adds nothing.
        self.write(DP_MSA_COLORIMETRY, (depth.code() << 5) << 24)?;
        self.write(DP_MSA_MISC, misc1)?;
        self.write(DP_MSA_TIMING_PARAM1, timing.v_total | timing.h_total << 16)?;
        self.write(DP_MSA_TIMING_PARAM2, v_start | h_start << 16)?;
        self.write(
            DP_MSA_TIMING_PARAM3,
            timing.v_sync_width
                | u32::from(!timing.v_sync_positive) << 15
                | timing.h_sync_width << 16
                | u32::from(!timing.h_sync_positive) << 31,
        )?;
        self.write(
            DP_MSA_TIMING_PARAM4,
            timing.v_active | timing.h_active << 16,
        )?;
        self.update(
            DP_SEC_FRAMING4,
            DP_SST_SDP_SPLITTING,
            if sdp_split { DP_SST_SDP_SPLITTING } else { 0 },
        )
    }
    /// `vpg3_update_generic_info_packet(index, packet, immediate = true)`.
    async fn vpg_packet(&mut self, index: u32, packet: &[u8; 36]) -> Result<(), Error> {
        let status = self.reg(VPG_GENERIC_STATUS);
        if !self
            .regs
            .wait(status, VPG_GENERIC_CONFLICT_OCCURED, 0, 10, 50)
            .await?
        {
            return Err(Error::Hdmi(crate::amdgpu_dcn30_hdmi::Error::Conflict));
        }
        self.regs
            .update(status, VPG_GENERIC_CONFLICT_CLR, VPG_GENERIC_CONFLICT_CLR)?;
        self.update(VPG_GENERIC_PACKET_ACCESS_CTRL, 0xff, index * 9)?;
        for word in packet.chunks_exact(4) {
            self.write(
                VPG_GENERIC_PACKET_DATA,
                u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
            )?;
        }
        self.update(VPG_GSP_IMMEDIATE_UPDATE_CTRL, 1 << index, 1 << index)
    }
    /// `enc3_stream_encoder_update_dp_info_packets` with only a VSC SDP
    /// (or nothing): VPG generic 0 and 1, GSP0 enabled, the secondary
    /// stream on while anything is.
    pub async fn update_info_packets(&mut self, vsc: Option<&[u8; 36]>) -> Result<(), Error> {
        if let Some(vsc) = vsc {
            self.vpg_packet(0, vsc).await?;
            self.vpg_packet(1, vsc).await?;
        }
        self.update(
            DP_SEC_CNTL,
            DP_SEC_GSP0_ENABLE,
            if vsc.is_some() { DP_SEC_GSP0_ENABLE } else { 0 },
        )?;
        if self.read(DP_SEC_CNTL)? != 0 {
            self.update(DP_SEC_CNTL, DP_SEC_STREAM_ENABLE, DP_SEC_STREAM_ENABLE)?;
        }
        Ok(())
    }
    /// `enc1_stream_encoder_stop_dp_info_packets`: every GSP, MPG and the
    /// secondary stream off in one write.
    pub fn stop_info_packets(&mut self) -> Result<(), Error> {
        self.write(DP_SEC_CNTL, 0)?;
        if self.read(DP_SEC_CNTL)? != 0 {
            self.update(DP_SEC_CNTL, DP_SEC_STREAM_ENABLE, DP_SEC_STREAM_ENABLE)?;
        }
        Ok(())
    }
    /// `enc3_dp_set_odm_combine(false)` and `enc2_stream_encoder_dp_unblank`:
    /// seed M/N against the trained link (`rate` is the DPCD code), hand it to
    /// the generator, then restart the stream with the frontend and steering
    /// FIFO reset.
    pub async fn unblank(&mut self, pixel_khz: u32, rate: u8) -> Result<(), Error> {
        self.update(DP_PIXEL_FORMAT, DP_PIXEL_COMBINE, 0)?;
        let link_khz = u64::from(rate) * u64::from(LINK_RATE_REF_KHZ);
        if link_khz == 0 {
            return Err(Error::Invalid);
        }
        let m_vid = N_VID * u64::from(pixel_khz) / link_khz;
        if m_vid == 0 || m_vid > 0x00ff_ffff {
            return Err(Error::Invalid);
        }
        self.update(DP_VID_TIMING, DP_VID_M_N_GEN_EN, 0)?;
        self.update(DP_VID_N, 0x00ff_ffff, N_VID as u32)?;
        self.update(DP_VID_M, 0x00ff_ffff, m_vid as u32)?;
        self.update(
            DP_VID_TIMING,
            DP_VID_M_N_GEN_EN | DP_VID_N_MUL,
            DP_VID_M_N_GEN_EN,
        )?;
        self.update(DP_VID_STREAM_CNTL, DP_VID_STREAM_ENABLE, 0)?;
        let reg = self.reg(DP_VID_STREAM_CNTL);
        // 5000 polls 10 us apart; Linux carries on after a timeout.
        self.regs
            .wait(reg, DP_VID_STREAM_STATUS, 0, 10, 5000)
            .await?;
        self.update(DIG_FE_CNTL, DIG_START, DIG_START)?;
        sleep_us(1).await;
        self.update(DIG_FE_CNTL, DIG_START, 0)?;
        self.update(DP_STEER_FIFO, DP_STEER_FIFO_RESET, DP_STEER_FIFO_RESET)?;
        sleep_us(10).await;
        self.update(DP_STEER_FIFO, DP_STEER_FIFO_RESET, 0)?;
        sleep_us(100).await;
        self.update(
            DP_VID_STREAM_CNTL,
            DP_VID_STREAM_ENABLE,
            DP_VID_STREAM_ENABLE,
        )
    }
    /// `enc1_stream_encoder_dp_blank`.
    pub async fn blank(&mut self) -> Result<(), Error> {
        blank_stream(&mut self.regs, self.dcn2, self.fe).await
    }
}

/// The source half of one DIO DP link for `amdgpu_dcn30_dp_link`: the link
/// encoder plus the VBIOS transmitter table, as Linux's
/// `dcn20_link_encoder_enable_dp_output` / `dp_set_hw_training_pattern` /
/// `dcn10_link_encoder_dp_set_lane_settings` /
/// `dcn10_link_encoder_disable_output` drive them.
pub(crate) struct DioSource<'a> {
    pub(crate) link: Link,
    pub(crate) phy: &'a mut dyn Phy,
}
/// The VBIOS transmitter calls the link layer needs, bound to one connector.
pub(crate) trait Phy: Send {
    /// TRANSMITTER ENABLE in DP mode at `rate` x 27 MHz on `lanes` lanes.
    fn enable(&mut self, rate: u8, lanes: u8) -> Result<(), Error>;
    /// One SETUP_VSEMPH call with `lane_set` (DP_LANE_SET without the
    /// max-reached bits).
    fn lane_settings(&mut self, rate: u8, lanes: u8, lane_set: u8) -> Result<(), Error>;
    /// TRANSMITTER DISABLE in DP mode.
    fn disable(&mut self) -> Result<(), Error>;
}
impl link_layer::Source for DioSource<'_> {
    /// `enc1_configure_encoder`, then TRANSMITTER ENABLE.
    fn enable(&mut self, link: DpLink) -> Result<(), Error> {
        self.link.configure(link.lanes)?;
        self.phy.enable(link.rate, link.lanes)
    }
    fn pattern(&mut self, tps: link_layer::Tps) -> Result<(), Error> {
        use link_layer::Tps;
        self.link.training_pattern(match tps {
            Tps::Tps1 => 0,
            Tps::Tps2 => 1,
            Tps::Tps3 => 2,
            Tps::Tps4 => 3,
        })
    }
    fn video(&mut self) -> Result<(), Error> {
        self.link.passthrough()
    }
    /// One SETUP_VSEMPH per lane with the common swing and pre-emphasis.
    fn drive(&mut self, link: DpLink, swing: u8, pre: u8) -> Result<(), Error> {
        if swing > 3 || pre > 3 {
            return Err(Error::Invalid);
        }
        for _ in 0..link.lanes {
            self.phy
                .lane_settings(link.rate, link.lanes, swing | pre << 3)?;
        }
        Ok(())
    }
    /// `dcn10_link_encoder_disable_output` (only for an enabled DIG), then
    /// `link_encoder_disable`.
    fn disable(&mut self) -> Result<(), Error> {
        if self.link.enabled()? {
            self.phy.disable()?;
            self.link.reset()?;
        }
        Ok(())
    }
}
