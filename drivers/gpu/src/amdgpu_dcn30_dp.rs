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
//! Scope: 8b/10b SST, RGB, 6/8/10 bpc, no MST/DSC/FEC/PSR, no LTTPR.
use crate::{
    amdgpu_dcn30_takeover::Regs, amdgpu_dml::Timing, amdgpu_dp_training as training,
    amdgpu_navi22_modeset::Error,
};
use core::future::Future;

// linux-ctx: hdr=dcn seg=2
// linux: mmDIG1_DIG_FE_CNTL - mmDIG0_DIG_FE_CNTL
const STRIDE: u64 = 0x100;
// VPG (per frontend).
// linux: mmVPG0_VPG_GENERIC_PACKET_ACCESS_CTRL
const VPG_GENERIC_PACKET_ACCESS_CTRL: u64 = 0x2068;
// linux: mmVPG0_VPG_GENERIC_PACKET_DATA
const VPG_GENERIC_PACKET_DATA: u64 = 0x2069;
// linux: mmVPG0_VPG_GSP_IMMEDIATE_UPDATE_CTRL
const VPG_GSP_IMMEDIATE_UPDATE_CTRL: u64 = 0x206b;
// linux: mmVPG0_VPG_GENERIC_STATUS
const VPG_GENERIC_STATUS: u64 = 0x206c;
// linux: VPG0_VPG_GENERIC_STATUS__VPG_GENERIC_CONFLICT_OCCURED_MASK
const VPG_GENERIC_CONFLICT_OCCURED: u32 = 1 << 1;
// linux: VPG0_VPG_GENERIC_STATUS__VPG_GENERIC_CONFLICT_CLR_MASK
const VPG_GENERIC_CONFLICT_CLR: u32 = 1 << 4;
// DIG frontend.
// linux: mmDIG0_DIG_FE_CNTL
const DIG_FE_CNTL: u64 = 0x208b;
// linux: DIG0_DIG_FE_CNTL__DIG_START_MASK
const DIG_START: u32 = 1 << 10;
// DIG backend / DP link (per transmitter).
// linux: mmDIG0_DIG_BE_EN_CNTL
const DIG_BE_EN_CNTL: u64 = 0x20b1;
// linux: DIG0_DIG_BE_EN_CNTL__DIG_ENABLE_MASK
const DIG_ENABLE: u32 = 1 << 0;
// linux: mmDP0_DP_LINK_CNTL
const DP_LINK_CNTL: u64 = 0x2108;
// linux: DP0_DP_LINK_CNTL__DP_LINK_TRAINING_COMPLETE_MASK
const DP_LINK_TRAINING_COMPLETE: u32 = 1 << 4;
// linux: mmDP0_DP_CONFIG
const DP_CONFIG: u64 = 0x210b;
// linux: mmDP0_DP_DPHY_INTERNAL_CTRL
const DP_DPHY_INTERNAL_CTRL: u64 = 0x210f;
// linux: mmDP0_DP_LINK_FRAMING_CNTL
const DP_LINK_FRAMING_CNTL: u64 = 0x2113;
// linux: DP0_DP_LINK_FRAMING_CNTL__DP_IDLE_BS_INTERVAL_MASK
const DP_IDLE_BS_INTERVAL: u32 = 0x0003_ffff;
// linux: DP0_DP_LINK_FRAMING_CNTL__DP_VBID_DISABLE_MASK
const DP_VBID_DISABLE: u32 = 1 << 24;
// linux: DP0_DP_LINK_FRAMING_CNTL__DP_VID_ENHANCED_FRAME_MODE_MASK
const DP_VID_ENHANCED_FRAME_MODE: u32 = 1 << 28;
// linux: mmDP0_DP_DPHY_CNTL
const DP_DPHY_CNTL: u64 = 0x2117;
// linux: DP0_DP_DPHY_CNTL__DPHY_BYPASS_MASK
const DPHY_BYPASS: u32 = 1 << 16;
// linux: mmDP0_DP_DPHY_TRAINING_PATTERN_SEL
const DP_DPHY_TRAINING_PATTERN_SEL: u64 = 0x2118;
// linux: mmDP0_DP_DPHY_PRBS_CNTL
const DP_DPHY_PRBS_CNTL: u64 = 0x211d;
// linux: DP0_DP_DPHY_PRBS_CNTL__DPHY_PRBS_EN_MASK
const DPHY_PRBS_EN: u32 = 1 << 0;
// linux: mmDP0_DP_DPHY_SCRAM_CNTL
const DP_DPHY_SCRAM_CNTL: u64 = 0x211e;
// linux: DP0_DP_DPHY_SCRAM_CNTL__DPHY_SCRAMBLER_ADVANCE_MASK
const DPHY_SCRAMBLER_ADVANCE: u32 = 1 << 4;
// linux: DP0_DP_DPHY_SCRAM_CNTL__DPHY_SCRAMBLER_BS_COUNT_MASK
const DPHY_SCRAMBLER_BS_COUNT: u32 = 0x0003_ff00;
// DP stream (per frontend).
// linux: mmDP0_DP_PIXEL_FORMAT
const DP_PIXEL_FORMAT: u64 = 0x2109;
// linux: DP0_DP_PIXEL_FORMAT__DP_PIXEL_ENCODING_MASK
const DP_PIXEL_ENCODING: u32 = 0x0000_0007;
// linux: DP0_DP_PIXEL_FORMAT__DP_COMPONENT_DEPTH_MASK
const DP_COMPONENT_DEPTH: u32 = 0x0700_0000;
// linux: DP0_DP_PIXEL_FORMAT__DP_PIXEL_COMBINE_MASK
const DP_PIXEL_COMBINE: u32 = 0x3000_0000;
// linux: mmDP0_DP_MSA_COLORIMETRY
const DP_MSA_COLORIMETRY: u64 = 0x210a;
// linux: mmDP0_DP_VID_STREAM_CNTL
const DP_VID_STREAM_CNTL: u64 = 0x210c;
// linux: DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_ENABLE_MASK
const DP_VID_STREAM_ENABLE: u32 = 1 << 0;
// linux: DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_DIS_DEFER_MASK
const DP_VID_STREAM_DIS_DEFER: u32 = 0x0000_0300;
// linux: DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_STATUS_MASK
const DP_VID_STREAM_STATUS: u32 = 1 << 16;
// linux: mmDP0_DP_STEER_FIFO
const DP_STEER_FIFO: u64 = 0x210d;
// linux: DP0_DP_STEER_FIFO__DP_STEER_FIFO_RESET_MASK
const DP_STEER_FIFO_RESET: u32 = 1 << 0;
// linux: mmDP0_DP_MSA_MISC
const DP_MSA_MISC: u64 = 0x210e;
// linux: mmDP0_DP_VID_TIMING
const DP_VID_TIMING: u64 = 0x2110;
// linux: DP0_DP_VID_TIMING__DP_VID_M_N_GEN_EN_MASK
const DP_VID_M_N_GEN_EN: u32 = 1 << 8;
// linux: DP0_DP_VID_TIMING__DP_VID_N_MUL_MASK
const DP_VID_N_MUL: u32 = 0x0000_0c00;
// linux: mmDP0_DP_VID_N
const DP_VID_N: u64 = 0x2111;
// linux: mmDP0_DP_VID_M
const DP_VID_M: u64 = 0x2112;
// linux: mmDP0_DP_SEC_CNTL
const DP_SEC_CNTL: u64 = 0x212b;
// linux: DP0_DP_SEC_CNTL__DP_SEC_STREAM_ENABLE_MASK
const DP_SEC_STREAM_ENABLE: u32 = 1 << 0;
// linux: DP0_DP_SEC_CNTL__DP_SEC_GSP0_ENABLE_MASK
const DP_SEC_GSP0_ENABLE: u32 = 1 << 20;
// linux: mmDP0_DP_SEC_FRAMING4
const DP_SEC_FRAMING4: u64 = 0x2130;
// linux: DP0_DP_SEC_FRAMING4__DP_SST_SDP_SPLITTING_MASK
const DP_SST_SDP_SPLITTING: u32 = 1 << 0;
// linux: mmDP0_DP_MSA_TIMING_PARAM1
const DP_MSA_TIMING_PARAM1: u64 = 0x214c;
// linux: mmDP0_DP_MSA_TIMING_PARAM2
const DP_MSA_TIMING_PARAM2: u64 = 0x214d;
// linux: mmDP0_DP_MSA_TIMING_PARAM3
const DP_MSA_TIMING_PARAM3: u64 = 0x214e;
// linux: mmDP0_DP_MSA_TIMING_PARAM4
const DP_MSA_TIMING_PARAM4: u64 = 0x214f;
/// The highest dword this module touches, for the bank bound.
// linux: mmDP5_DP_MSA_TIMING_PARAM4
pub(crate) const LAST_REG: u32 = (DP_MSA_TIMING_PARAM4 + 5 * STRIDE) as u32;
/// `enc2_stream_encoder_dp_unblank`'s fixed N.
// linux-ctx: reset
// linux: n/a (literal n_vid = 0x8000 in dcn20_stream_encoder.c:enc2_stream_encoder_dp_unblank)
const N_VID: u64 = 0x8000;
/// `LINK_RATE_REF_FREQ_IN_KHZ`.
// linux: n/a (LINK_RATE_REF_FREQ_IN_KHZ = 27000, include/link_service_types.h; not in checker sets)
pub const LINK_RATE_REF_KHZ: u32 = 27_000;
/// DPCD addresses this module's callers use.
// linux: DP_SET_POWER
pub const DPCD_SET_POWER: u32 = 0x600;
// linux: DP_DPRX_FEATURE_ENUMERATION_LIST
pub const DPCD_DPRX_FEATURE_ENUMERATION_LIST: u32 = 0x2210;
/// `DP_SET_POWER_D3` (`dp_disable_link_phy` → `dpcd_write_rx_power_ctrl`).
pub const SET_POWER_D3: u8 = 2; // linux: DP_SET_POWER_D3

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
            // linux: n/a (DP_COMPONENT_PIXEL_DEPTH_6BPC = 0, dc/inc/hw/stream_encoder.h; not in checker sets)
            Depth::Bpc6 => 0,
            // linux: n/a (DP_COMPONENT_PIXEL_DEPTH_8BPC = 1, dc/inc/hw/stream_encoder.h; not in checker sets)
            Depth::Bpc8 => 1,
            // linux: n/a (DP_COMPONENT_PIXEL_DEPTH_10BPC = 2, dc/inc/hw/stream_encoder.h; not in checker sets)
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
    // linux-lit: 0x07=DP_SDP_VSC
    p[..4].copy_from_slice(&[0x00, 0x07, 0x05, 0x13]);
    // linux: n/a (VSC SDP DB17 at SB17; info_packet.c:mod_build_vsc_infopacket)
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
    // linux-lit: 8=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_DIS_DEFER__SHIFT
    regs.update(reg(DP_VID_STREAM_CNTL), DP_VID_STREAM_DIS_DEFER, 2 << 8)?;
    regs.update(reg(DP_VID_STREAM_CNTL), DP_VID_STREAM_ENABLE, 0)?;
    // DP_BLANK_MAX_RETRY * 501 polls 10 us apart; Linux logs a timeout.
    regs.wait(
        reg(DP_VID_STREAM_CNTL),
        DP_VID_STREAM_STATUS,
        0,
        // linux: n/a (REG_WAIT 10 us, literal in dcn10_stream_encoder.c:enc1_stream_encoder_dp_blank)
        10,
        // linux: n/a (DP_BLANK_MAX_RETRY * 501; local #define 20 in dcn10_stream_encoder.c)
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
        // linux: n/a (NARF bound: six DIG backends)
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
        // linux-lit: 1=LANE_COUNT_ONE; 2=LANE_COUNT_TWO; 4=LANE_COUNT_FOUR
        if !matches!(lanes, 1 | 2 | 4) {
            return Err(Error::Invalid);
        }
        self.write(DP_CONFIG, u32::from(lanes - 1))?; // linux-lit: 1=LANE_COUNT_ONE
        self.update(
            DP_DPHY_SCRAM_CNTL,
            DPHY_SCRAMBLER_ADVANCE,
            DPHY_SCRAMBLER_ADVANCE,
        )
    }
    /// `dcn10_link_encoder_set_dp_phy_pattern_training_pattern`: TPS1..4 as
    /// index 0..3.
    pub fn training_pattern(&mut self, index: u8) -> Result<(), Error> {
        // linux: n/a (TPS1..TPS4 as DP_DPHY_TRAINING_PATTERN_SEL 0..3, dcn10_link_encoder.c)
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
            // linux: n/a (DP_IDLE_BS_INTERVAL 0x2000, literal in dcn10_link_encoder.c:set_dp_phy_pattern_passthrough_mode)
            0x2000 | DP_VID_ENHANCED_FRAME_MODE,
        )?;
        // linux-lit: 8=DP0_DP_DPHY_SCRAM_CNTL__DPHY_SCRAMBLER_BS_COUNT__SHIFT
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
        // linux: n/a (NARF bound: six DIG frontends)
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
            // linux-lit: 0xffff=DP0_DP_MSA_TIMING_PARAM1__DP_MSA_VTOTAL_MASK
            if value == 0 || value > 0xffff {
                return Err(Error::Invalid);
            }
        }
        // linux-lit: 0x7fff=DP0_DP_MSA_TIMING_PARAM3__DP_MSA_VSYNCWIDTH_MASK
        if timing.h_sync_width > 0x7fff || timing.v_sync_width > 0x7fff {
            return Err(Error::Invalid);
        }
        self.update(
            DP_PIXEL_FORMAT,
            DP_PIXEL_ENCODING | DP_COMPONENT_DEPTH,
            depth.code() << DP_COMPONENT_DEPTH.trailing_zeros(),
        )?;
        // MISC1 bit 6: colorimetry from the VSC SDP; bit 7 clear for sRGB.
        // linux: n/a (MISC1 bits 0x80/0x40, literals in dcn10_stream_encoder.c:enc1_stream_encoder_dp_set_stream_attribute)
        let misc1 = self.read(DP_MSA_MISC)? & !0xc0 | if vsc_colorimetry { 0x40 } else { 0 };
        // MISC0: bpc in bits 7:5; RGB full range adds nothing.
        // linux-lit: 24=DP0_DP_MSA_COLORIMETRY__DP_MSA_MISC0__SHIFT
        self.write(DP_MSA_COLORIMETRY, (depth.code() << 5) << 24)?;
        self.write(DP_MSA_MISC, misc1)?;
        // linux-lit: 16=DP0_DP_MSA_TIMING_PARAM1__DP_MSA_HTOTAL__SHIFT
        self.write(DP_MSA_TIMING_PARAM1, timing.v_total | timing.h_total << 16)?;
        // linux-lit: 16=DP0_DP_MSA_TIMING_PARAM2__DP_MSA_HSTART__SHIFT
        self.write(DP_MSA_TIMING_PARAM2, v_start | h_start << 16)?;
        self.write(
            DP_MSA_TIMING_PARAM3,
            timing.v_sync_width
                // linux-lit: 15=DP0_DP_MSA_TIMING_PARAM3__DP_MSA_VSYNCPOLARITY__SHIFT
                | u32::from(!timing.v_sync_positive) << 15
                // linux-lit: 16=DP0_DP_MSA_TIMING_PARAM3__DP_MSA_HSYNCWIDTH__SHIFT
                | timing.h_sync_width << 16
                // linux-lit: 31=DP0_DP_MSA_TIMING_PARAM3__DP_MSA_HSYNCPOLARITY__SHIFT
                | u32::from(!timing.h_sync_positive) << 31,
        )?;
        self.write(
            DP_MSA_TIMING_PARAM4,
            // linux-lit: 16=DP0_DP_MSA_TIMING_PARAM4__DP_MSA_HWIDTH__SHIFT
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
            // linux: n/a (10 us x 50 retries, literals in dcn30_vpg.c:vpg3_update_generic_info_packet)
            .wait(status, VPG_GENERIC_CONFLICT_OCCURED, 0, 10, 50)
            .await?
        {
            return Err(Error::Hdmi(crate::amdgpu_dcn30_hdmi::Error::Conflict));
        }
        self.regs
            .update(status, VPG_GENERIC_CONFLICT_CLR, VPG_GENERIC_CONFLICT_CLR)?;
        // linux-lit: 0xff=VPG0_VPG_GENERIC_PACKET_ACCESS_CTRL__VPG_GENERIC_DATA_INDEX_MASK
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
        // linux-lit: 0x00ff_ffff=DP0_DP_VID_M__DP_VID_M_MASK
        if m_vid == 0 || m_vid > 0x00ff_ffff {
            return Err(Error::Invalid);
        }
        self.update(DP_VID_TIMING, DP_VID_M_N_GEN_EN, 0)?;
        // linux-lit: 0x00ff_ffff=DP0_DP_VID_N__DP_VID_N_MASK
        self.update(DP_VID_N, 0x00ff_ffff, N_VID as u32)?;
        // linux-lit: 0x00ff_ffff=DP0_DP_VID_M__DP_VID_M_MASK
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
            // linux: n/a (REG_WAIT 10 us x 5000, literals in dcn20_stream_encoder.c:enc2_stream_encoder_dp_unblank)
            .wait(reg, DP_VID_STREAM_STATUS, 0, 10, 5000)
            .await?;
        self.update(DIG_FE_CNTL, DIG_START, DIG_START)?;
        sleep_us(1).await; // linux: n/a (udelay(1), literal in enc2_stream_encoder_dp_unblank)
        self.update(DIG_FE_CNTL, DIG_START, 0)?;
        self.update(DP_STEER_FIFO, DP_STEER_FIFO_RESET, DP_STEER_FIFO_RESET)?;
        sleep_us(10).await; // linux: n/a (udelay(10), literal in enc2_stream_encoder_dp_unblank)
        self.update(DP_STEER_FIFO, DP_STEER_FIFO_RESET, 0)?;
        sleep_us(100).await; // linux: n/a (udelay(100), literal in enc2_stream_encoder_dp_unblank)
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

/// The source side of 8b/10b training for [`training::train`]: the DIO link
/// encoder plus the VBIOS transmitter table, driven per Linux
/// `dp_enable_link_phy` / `dp_set_hw_training_pattern` /
/// `dp_set_hw_lane_settings` / `dp_disable_link_phy`.
pub(crate) struct Trainer<'a, A: Aux> {
    pub(crate) aux: &'a mut A,
    pub(crate) link: Link,
    pub(crate) phy: &'a mut dyn Phy,
    pub(crate) settings: Option<training::Settings>,
}
/// The VBIOS transmitter calls the trainer needs, bound to one connector.
pub(crate) trait Phy: Send {
    /// TRANSMITTER ENABLE in DP mode at `rate` x 27 MHz on `lanes` lanes.
    fn enable(&mut self, rate: u8, lanes: u8) -> Result<(), Error>;
    /// One SETUP_VSEMPH call with `lane_set` (DP_LANE_SET without the
    /// max-reached bits).
    fn lane_settings(&mut self, rate: u8, lanes: u8, lane_set: u8) -> Result<(), Error>;
    /// TRANSMITTER DISABLE in DP mode.
    fn disable(&mut self) -> Result<(), Error>;
}
fn transport(error: Error) -> training::Error {
    match error {
        Error::Bios(_) | Error::Block(_) | Error::Invalid => training::Error::Source,
        _ => training::Error::Aux,
    }
}
impl<A: Aux + Send> training::LinkIo for Trainer<'_, A> {
    async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), training::Error> {
        self.aux
            .read(address, data)
            .await
            .map_err(|_| training::Error::Aux)
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), training::Error> {
        self.aux
            .write(address, data)
            .await
            .map_err(|_| training::Error::Aux)
    }
    /// `dp_enable_link_phy` → `dcn10_link_encoder_enable_dp_output`.
    async fn configure(&mut self, settings: training::Settings) -> Result<(), training::Error> {
        self.settings = Some(settings);
        self.link.configure(settings.lanes).map_err(transport)?;
        self.phy
            .enable(settings.rate, settings.lanes)
            .map_err(transport)
    }
    async fn pattern(&mut self, pattern: u8) -> Result<(), training::Error> {
        let index = match pattern {
            // linux-lit: 0=DP_TRAINING_PATTERN_DISABLE
            0 => return self.link.passthrough().map_err(transport),
            1 => 0, // linux-lit: 1=DP_TRAINING_PATTERN_1
            2 => 1, // linux-lit: 2=DP_TRAINING_PATTERN_2
            3 => 2, // linux-lit: 3=DP_TRAINING_PATTERN_3
            7 => 3, // linux-lit: 7=DP_TRAINING_PATTERN_4
            _ => return Err(training::Error::Invalid),
        };
        self.link.training_pattern(index).map_err(transport)
    }
    /// `dcn10_link_encoder_dp_set_lane_settings`: one call per lane with the
    /// common (`disallow_per_lane_settings`) swing and pre-emphasis.
    async fn tune(&mut self, lanes: &[u8]) -> Result<(), training::Error> {
        let settings = self.settings.ok_or(training::Error::Invalid)?;
        for &set in lanes {
            self.phy
                // linux-lit: 0x1b=DP_TRAIN_VOLTAGE_SWING_MASK | DP_TRAIN_PRE_EMPHASIS_MASK
                .lane_settings(settings.rate, settings.lanes, set & 0x1b)
                .map_err(transport)?;
        }
        Ok(())
    }
    /// `dp_disable_link_phy`'s source half: `dcn10_link_encoder_disable_output`
    /// (only for an enabled DIG), then `link_encoder_disable`.
    async fn disable(&mut self) -> Result<(), training::Error> {
        if self.link.enabled().map_err(transport)? {
            self.phy.disable().map_err(transport)?;
            self.link.reset().map_err(transport)?;
        }
        self.settings = None;
        Ok(())
    }
    async fn delay_us(&mut self, microseconds: u32) {
        sleep_us(u64::from(microseconds)).await;
    }
}
