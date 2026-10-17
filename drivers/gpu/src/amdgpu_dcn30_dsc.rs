//! Navi22 DCN3.0 Display Stream Compression on DisplayPort SST: DCN3.0
//! carries DCN2.0's DSC engine (`dcn20_dsc.c`, one engine per pipe, DSC n
//! fed by OPP n) and the DIO stream encoder's DSC half, as Linux's
//! `link_set_dpms_on` drives them:
//!
//! - before the link: the engine's power domain (`dcn20_dsc_pg_control`,
//!   DOMAIN16 + n), `dsc2_set_config` (`dsc_write_to_registers`) and
//!   `dsc2_enable` from the OPP, the stream encoder's DSC mode
//!   (`enc3_dp_set_dsc_config`) and the OPTC's (`optc3_set_dsc_config`);
//! - around training: FEC ready on both ends (`dp_set_fec_ready`), FEC on
//!   after the link trained (`dp_set_fec_enable`);
//! - after `enable_stream`: DSC on in the sink (`dp_set_dsc_on_rx`, DPCD
//!   DSC_ENABLE) and the PPS SDP (`enc3_dp_set_dsc_pps_info_packet`, VPG
//!   generic packets 11..14 sent every frame on GSP11).
//!
//! With ODM 2:1 each half's DSC compresses half the line with half the
//! slices. The register values come from the shared [`crate::amdgpu_dsc`]
//! (`dsc_prepare_config`); the decision uses DCN2.0's encoder caps
//! (`dsc2_get_enc_caps`). Offsets and masks are `dcn_3_0_0_offset.h` /
//! `_sh_mask.h` at DCN base index 2.
use crate::{
    amdgpu_dcn30_dp::Aux,
    amdgpu_dcn30_takeover::Regs,
    amdgpu_dml::Timing,
    amdgpu_dsc::{self, DscConfig, DscRegisters, DscSinkCaps, DscTiming, Encoding, PixelFormat},
    amdgpu_navi22_modeset::Error,
};
use alloc::vec::Vec;

// DSC_TOP0 .. DSC_TOP5, 0x5c apart.
const DSC_BASE: u64 = 0x3000; // linux: mmDSC_TOP0_DSC_TOP_CONTROL
const DSC_STRIDE: u64 = 0x5c; // linux: mmDSC_TOP1_DSC_TOP_CONTROL - mmDSC_TOP0_DSC_TOP_CONTROL
const TOP_CONTROL: u64 = 0x0; // linux: mmDSC_TOP0_DSC_TOP_CONTROL - mmDSC_TOP0_DSC_TOP_CONTROL
const DSC_CLOCK_EN: u32 = 1 << 0; // linux: DSC_TOP0_DSC_TOP_CONTROL__DSC_CLOCK_EN_MASK
const DEBUG_CONTROL: u64 = 0x1; // linux: mmDSC_TOP0_DSC_DEBUG_CONTROL - mmDSC_TOP0_DSC_TOP_CONTROL
const CIF_CONFIG0: u64 = 0x5; // linux: mmDSCCIF0_DSCCIF_CONFIG0 - mmDSC_TOP0_DSC_TOP_CONTROL
const CIF_CONFIG1: u64 = 0x6; // linux: mmDSCCIF0_DSCCIF_CONFIG1 - mmDSC_TOP0_DSC_TOP_CONTROL
const CONFIG0: u64 = 0xa; // linux: mmDSCC0_DSCC_CONFIG0 - mmDSC_TOP0_DSC_TOP_CONTROL
const CONFIG1: u64 = 0xb; // linux: mmDSCC0_DSCC_CONFIG1 - mmDSC_TOP0_DSC_TOP_CONTROL
const INTERRUPT_CONTROL_STATUS: u64 = 0xd; // linux: mmDSCC0_DSCC_INTERRUPT_CONTROL_STATUS - mmDSC_TOP0_DSC_TOP_CONTROL
const PPS_CONFIG0: u64 = 0xe; // linux: mmDSCC0_DSCC_PPS_CONFIG0 - mmDSC_TOP0_DSC_TOP_CONTROL
/// `DSCRM0_DSCRM_DSC_FORWARD_CONFIG`; DSCRM n follows.
const FORWARD: u64 = 0x1a64; // linux: mmDSCRM0_DSCRM_DSC_FORWARD_CONFIG
const FORWARD_EN: u32 = 1 << 0; // linux: DSCRM0_DSCRM_DSC_FORWARD_CONFIG__DSCRM_DSC_FORWARD_EN_MASK
const FORWARD_OPP: u32 = 0x70; // linux: DSCRM0_DSCRM_DSC_FORWARD_CONFIG__DSCRM_DSC_OPP_PIPE_SOURCE_MASK
                               // DSC power domains 16..21, CONFIG then STATUS.
const DOMAIN16_PG_CONFIG: u64 = 0x00a1; // linux: mmDOMAIN16_PG_CONFIG
const POWER_GATE: u32 = 1 << 8; // linux: DOMAIN16_PG_CONFIG__DOMAIN16_POWER_GATE_MASK
const PGFSM_PWR_STATUS: u32 = 0xc000_0000; // linux: DOMAIN16_PG_STATUS__DOMAIN16_PGFSM_PWR_STATUS_MASK
const DC_IP_REQUEST_CNTL: u64 = 0x00b2; // linux: mmDC_IP_REQUEST_CNTL
                                        // OPTC (ODM n, stride 0x10) and OTG (stride 0x80).
const ODM_STRIDE: u64 = 0x10; // linux: mmODM1_OPTC_DATA_FORMAT_CONTROL - mmODM0_OPTC_DATA_FORMAT_CONTROL
const OPTC_DATA_FORMAT_CONTROL: u64 = 0x1acc; // linux: mmODM0_OPTC_DATA_FORMAT_CONTROL
const OPTC_DSC_MODE: u32 = 0x30; // linux: ODM0_OPTC_DATA_FORMAT_CONTROL__OPTC_DSC_MODE_MASK
const OPTC_BYTES_PER_PIXEL: u64 = 0x1acd; // linux: mmODM0_OPTC_BYTES_PER_PIXEL
const OPTC_WIDTH_CONTROL: u64 = 0x1ace; // linux: mmODM0_OPTC_WIDTH_CONTROL
const OPTC_DSC_SLICE_WIDTH: u32 = 0x1fff_0000; // linux: ODM0_OPTC_WIDTH_CONTROL__OPTC_DSC_SLICE_WIDTH_MASK
const OTG_STRIDE: u64 = 0x80; // linux: mmOTG1_OTG_V_SYNC_A_CNTL - mmOTG0_OTG_V_SYNC_A_CNTL
const OTG_V_SYNC_A_CNTL: u64 = 0x1b38; // linux: mmOTG0_OTG_V_SYNC_A_CNTL
const OTG_V_SYNC_MODE: u32 = 1 << 8; // linux: OTG0_OTG_V_SYNC_A_CNTL__OTG_V_SYNC_MODE_MASK
                                     // DIO frontend / link blocks, stride 0x100.
const DIO_STRIDE: u64 = 0x100; // linux: mmVPG1_VPG_GENERIC_PACKET_ACCESS_CTRL - mmVPG0_VPG_GENERIC_PACKET_ACCESS_CTRL
const VPG_GENERIC_PACKET_ACCESS_CTRL: u64 = 0x2068; // linux: mmVPG0_VPG_GENERIC_PACKET_ACCESS_CTRL
const VPG_GENERIC_PACKET_DATA: u64 = 0x2069; // linux: mmVPG0_VPG_GENERIC_PACKET_DATA
const VPG_GSP_IMMEDIATE_UPDATE_CTRL: u64 = 0x206b; // linux: mmVPG0_VPG_GSP_IMMEDIATE_UPDATE_CTRL
const VPG_GENERIC_STATUS: u64 = 0x206c; // linux: mmVPG0_VPG_GENERIC_STATUS
const VPG_GENERIC_CONFLICT_OCCURED: u32 = 1 << 1; // linux: VPG0_VPG_GENERIC_STATUS__VPG_GENERIC_CONFLICT_OCCURED_MASK
const VPG_GENERIC_CONFLICT_CLR: u32 = 1 << 4; // linux: VPG0_VPG_GENERIC_STATUS__VPG_GENERIC_CONFLICT_CLR_MASK
const AFMT_CNTL: u64 = 0x20af; // linux: mmDIG0_AFMT_CNTL
const AFMT_AUDIO_CLOCK_EN: u32 = 1 << 0; // linux: DIG0_AFMT_CNTL__AFMT_AUDIO_CLOCK_EN_MASK
const DP_DPHY_CNTL: u64 = 0x2117; // linux: mmDP0_DP_DPHY_CNTL
const DPHY_FEC_EN: u32 = 1 << 4; // linux: DP0_DP_DPHY_CNTL__DPHY_FEC_EN_MASK
const DPHY_FEC_READY_SHADOW: u32 = 1 << 5; // linux: DP0_DP_DPHY_CNTL__DPHY_FEC_READY_SHADOW_MASK
const DP_SEC_CNTL: u64 = 0x212b; // linux: mmDP0_DP_SEC_CNTL
const DP_SEC_STREAM_ENABLE: u32 = 1 << 0; // linux: DP0_DP_SEC_CNTL__DP_SEC_STREAM_ENABLE_MASK
const DP_DSC_CNTL: u64 = 0x2152; // linux: mmDP0_DP_DSC_CNTL
const DP_DSC_MODE: u32 = 0x3; // linux: DP0_DP_DSC_CNTL__DP_DSC_MODE_MASK
const DP_DSC_SLICE_WIDTH: u32 = 0x1fff_0000; // linux: DP0_DP_DSC_CNTL__DP_DSC_SLICE_WIDTH_MASK
const DP_SEC_CNTL2: u64 = 0x2153; // linux: mmDP0_DP_SEC_CNTL2
const DP_SEC_GSP11_PPS: u32 = 1 << 28; // linux: DP0_DP_SEC_CNTL2__DP_SEC_GSP11_PPS_MASK
const DP_MSA_VBID_MISC: u64 = 0x215a; // linux: mmDP0_DP_MSA_VBID_MISC
const DP_VBID6_LINE_REFERENCE: u32 = 1 << 15; // linux: DP0_DP_MSA_VBID_MISC__DP_VBID6_LINE_REFERENCE_MASK
const DP_VBID6_LINE_NUM: u32 = 0xffff_0000; // linux: DP0_DP_MSA_VBID_MISC__DP_VBID6_LINE_NUM_MASK
const DP_SEC_METADATA_TRANSMISSION: u64 = 0x215b; // linux: mmDP0_DP_SEC_METADATA_TRANSMISSION
const DP_DSC_BYTES_PER_PIXEL: u64 = 0x215c; // linux: mmDP0_DP_DSC_BYTES_PER_PIXEL
const DP_GSP11_CNTL: u64 = 0x2161; // linux: mmDP0_DP_GSP11_CNTL
const DP_SEC_GSP11_ENABLE: u32 = 1 << 4; // linux: DP0_DP_GSP11_CNTL__DP_SEC_GSP11_ENABLE_MASK
const DP_SEC_GSP11_LINE_NUM: u32 = 0xffff_0000; // linux: DP0_DP_GSP11_CNTL__DP_SEC_GSP11_LINE_NUM_MASK
/// The highest dword this module touches, for the bank bound.
pub(crate) const LAST_REG: u32 = (DSC_BASE + 5 * DSC_STRIDE + PPS_CONFIG0 + 22) as u32;
/// DPCD: DSC caps, FEC capability, FEC configuration, DSC enable.
pub const DPCD_DSC_SUPPORT: u32 = 0x60; // linux: DP_DSC_SUPPORT
pub const DPCD_FEC_CAPABILITY: u32 = 0x90; // linux: DP_FEC_CAPABILITY
pub const DPCD_FEC_CONFIGURATION: u32 = 0x120; // linux: DP_FEC_CONFIGURATION
pub const DPCD_DSC_ENABLE: u32 = 0x160; // linux: DP_DSC_ENABLE
/// `DC_DP_INFOFRAME_TYPE_PPS`.
const SDP_TYPE_PPS: u8 = 0x10; // linux: DC_DP_INFOFRAME_TYPE_PPS
/// `optc_dsc_mode`.
const OPTC_DSC_ENABLED_444: u32 = 1; // linux: OPTC_DSC_ENABLED_444
const OPTC_DSC_ENABLED_NATIVE_SUBSAMPLED: u32 = 2; // linux: OPTC_DSC_ENABLED_NATIVE_SUBSAMPLED
/// `max_image_width` of one DCN2.0 engine.
pub const MAX_IMAGE_WIDTH: u32 = 5184; // linux: n/a (dcn20_dsc.c dsc2_get_enc_caps: max_slice_width 5184)

/// The DSC timing an 8-bpc RGB stream's DSC compresses.
pub fn dsc_timing(t: &Timing) -> DscTiming {
    DscTiming {
        pix_clk_100hz: t.pixel_clock_khz * 10,
        h_active: t.h_active,
        h_total: t.h_total,
        v_active: t.v_active,
        v_total: t.v_total,
        bpc: 8,
        encoding: Encoding::Rgb,
    }
}

/// What a DSC stream programs: the whole picture's registers (the PPS the
/// sink receives, the OPTC's and stream encoder's bytes per pixel and slice
/// width), and each engine's (halves with ODM 2:1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub config: DscConfig,
    pub picture: DscRegisters,
    pub engine: DscRegisters,
    pub odm: bool,
}

/// `dsc2_validate_stream` / `link_set_dsc_on_stream`'s per-engine
/// configuration: Linux's `dsc_cfg` with the picture width and the slice
/// count divided by the ODM segments. One engine takes at most four
/// slices and 5184 pixels.
pub fn plan(t: &Timing, config: &DscConfig, odm: bool) -> Result<Plan, Error> {
    let segments = if odm { 2 } else { 1 };
    if config.slices_h % segments != 0
        || config.slices_h / segments > 4
        || t.h_active % segments != 0
        || t.h_active / segments > MAX_IMAGE_WIDTH
    {
        return Err(Error::Unsupported);
    }
    let picture = amdgpu_dsc::prepare(&dsc_timing(t), config).ok_or(Error::Invalid)?;
    if !odm {
        return Ok(Plan {
            config: *config,
            picture,
            engine: picture,
            odm,
        });
    }
    let half = Timing {
        h_active: t.h_active / 2,
        h_total: t.h_total / 2,
        pixel_clock_khz: t.pixel_clock_khz / 2,
        ..*t
    };
    let cfg = DscConfig {
        slices_h: config.slices_h / 2,
        ..*config
    };
    let mut engine = amdgpu_dsc::prepare(&dsc_timing(&half), &cfg).ok_or(Error::Invalid)?;
    // dsc_cfg.is_odm: reset the ICH at every line end.
    engine.ich_reset_at_eol = 0xf;
    // Both halves slice the line the same way, so the OPTC and the encoder
    // see one slice width and byte rate either way.
    if engine.slice_width != picture.slice_width
        || engine.bytes_per_pixel != picture.bytes_per_pixel
    {
        return Err(Error::Invalid);
    }
    Ok(Plan {
        config: *config,
        picture,
        engine,
        odm,
    })
}

/// `apply_dsc_policy_for_stream` for an 8-bpc RGB DP SST stream: DSC only
/// when the uncompressed stream exceeds the trained link (`link_kbps`), at
/// the highest bpp that fits, and only with FEC (DP's DSC requires it).
/// `dsc_caps` is DPCD 0x60..0x6F and `fec_caps` DPCD 0x90.
pub fn select(t: &Timing, dsc_caps: &[u8; 16], fec_caps: u8, link_kbps: u32) -> Option<DscConfig> {
    if fec_caps & 1 == 0 {
        return None;
    }
    let sink = DscSinkCaps::parse(dsc_caps, &[0; 3])?;
    amdgpu_dsc::compute_config_dcn20(&sink, link_kbps, &dsc_timing(t), false)
}

/// `dsc_write_to_registers`' values for DSC registers 0x01..0x24 (offset,
/// value), each written whole (REG_SET) and masked to its fields.
fn engine_values(r: &DscRegisters) -> Vec<(u64, u32)> {
    let p = &r.pps;
    let bpc = u32::from(p.bits_per_component);
    let mut v = alloc::vec![
        (DEBUG_CONTROL, 0),
        (
            CIF_CONFIG0,
            (r.pixel_format as u32) << 12 & 0x7000 | bpc << 16 & 0xf_0000
        ),
        (
            CIF_CONFIG1,
            u32::from(p.pic_width) | u32::from(p.pic_height) << 16
        ),
        (
            CONFIG0,
            r.ich_reset_at_eol & 0xf
                | (r.slices_h - 1) << 4 & 0x30
                | u32::from(r.alternate_ich_encoding) << 8
                | (r.slices_v - 1) << 16,
        ),
        (CONFIG1, r.rc_buffer_model_size & 0x3_ffff),
        (INTERRUPT_CONTROL_STATUS, 0),
    ];
    let native = matches!(
        r.pixel_format,
        PixelFormat::Native422 | PixelFormat::Native420
    );
    let bpp = if native { r.bpp_x32 } else { r.bpp_x32 >> 1 };
    let pair = |a: u32, b: u32| a & 0xffff | b << 16;
    let range = |i: usize| {
        let (min, max, ofs) = p.rc_range_params[i];
        u32::from(min) & 0x1f | (u32::from(max) & 0x1f) << 5 | (u32::from(ofs) & 0x3f) << 10
    };
    let th = |i: usize| u32::from(p.rc_buf_thresh[i]) & 0xff;
    let pps = [
        u32::from(p.dsc_version_minor) & 0xf
            | (u32::from(p.line_buf_depth) & 0xf) << 24
            | (bpc & 0xf) << 28,
        bpp & 0x3ff
            | u32::from(r.pixel_format == PixelFormat::Simple422) << 11
            | u32::from(r.pixel_format == PixelFormat::Rgb) << 12
            | u32::from(p.block_pred_enable) << 13
            | u32::from(r.pixel_format == PixelFormat::Native422) << 14
            | u32::from(r.pixel_format == PixelFormat::Native420) << 15
            | u32::from(p.slice_chunk_size) << 16,
        pair(u32::from(p.pic_width), u32::from(p.pic_height)),
        pair(u32::from(p.slice_width), u32::from(p.slice_height)),
        u32::from(p.initial_xmit_delay) & 0x3ff,
        u32::from(p.initial_scale_value) & 0x3f | u32::from(p.scale_increment_interval) << 16,
        u32::from(p.scale_decrement_interval) & 0xfff
            | (u32::from(p.first_line_bpg_offset) & 0x1f) << 16
            | (u32::from(p.second_line_bpg_offset) & 0x1f) << 24,
        pair(u32::from(p.nfl_bpg_offset), u32::from(p.slice_bpg_offset)),
        pair(
            u32::from(p.nsl_bpg_offset),
            u32::from(p.second_line_offset_adj),
        ),
        pair(u32::from(p.initial_offset), u32::from(p.final_offset)),
        u32::from(p.flatness_min_qp) & 0x1f
            | (u32::from(p.flatness_max_qp) & 0x1f) << 8
            | u32::from(p.rc_model_size) << 16,
        u32::from(p.rc_edge_factor) & 0xf
            | (u32::from(p.rc_quant_incr_limit0) & 0x1f) << 8
            | (u32::from(p.rc_quant_incr_limit1) & 0x1f) << 16
            | (u32::from(p.rc_tgt_offset_low) & 0xf) << 24
            | (u32::from(p.rc_tgt_offset_high) & 0xf) << 28,
        th(0) | th(1) << 8 | th(2) << 16 | th(3) << 24,
        th(4) | th(5) << 8 | th(6) << 16 | th(7) << 24,
        th(8) | th(9) << 8 | th(10) << 16 | th(11) << 24,
        th(12) | th(13) << 8 | range(0) << 16,
        range(1) | range(2) << 16,
        range(3) | range(4) << 16,
        range(5) | range(6) << 16,
        range(7) | range(8) << 16,
        range(9) | range(10) << 16,
        range(11) | range(12) << 16,
        range(13) | range(14) << 16,
    ];
    v.extend(
        pps.iter()
            .enumerate()
            .map(|(i, &x)| (PPS_CONFIG0 + i as u64, x)),
    );
    v
}

/// `optc_dsc_mode` for the picture.
fn optc_mode(r: &DscRegisters) -> u32 {
    if r.is_444 {
        OPTC_DSC_ENABLED_444
    } else {
        OPTC_DSC_ENABLED_NATIVE_SUBSAMPLED
    }
}

/// The DSC engines, the OPTCs' DSC halves and the DIO's DSC/FEC halves.
#[derive(Clone, Copy, Debug)]
pub struct Dsc {
    regs: Regs,
    dcn2: u64,
}
impl Dsc {
    pub(crate) fn new(regs: Regs, dcn2: u64) -> Self {
        Self { regs, dcn2 }
    }
    fn at(&self, reg: u64) -> u64 {
        self.dcn2 + reg * 4
    }
    fn engine(&self, dsc: u8, reg: u64) -> u64 {
        self.at(DSC_BASE + u64::from(dsc) * DSC_STRIDE + reg)
    }
    fn dio(&self, block: u8, reg: u64) -> u64 {
        self.at(reg + u64::from(block) * DIO_STRIDE)
    }
    /// `dcn20_dsc_pg_control`: DSC `dsc`'s domain (16 + n) gated or not,
    /// then up to 1000 polls 1 us apart for the power state; IP requests
    /// enabled around it. Linux only logs a timeout; powering up fails
    /// closed here (a gated engine would never compress), powering down is
    /// left to the caller.
    pub async fn power(&mut self, dsc: u8, on: bool) -> Result<bool, Error> {
        if dsc >= 6 {
            return Err(Error::Invalid);
        }
        let request = self.at(DC_IP_REQUEST_CNTL);
        let original = self.regs.read(request)? & 1;
        if original == 0 {
            self.regs.write(request, 1)?;
        }
        let config = self.at(DOMAIN16_PG_CONFIG + 2 * u64::from(dsc));
        let result = async {
            self.regs
                .update(config, POWER_GATE, if on { 0 } else { POWER_GATE })?;
            self.regs
                .wait(
                    config + 4,
                    PGFSM_PWR_STATUS,
                    if on { 0 } else { 2 << 30 },
                    1,
                    1000,
                )
                .await
        }
        .await;
        if original == 0 {
            let _ = self.regs.write(request, 0);
        }
        result
    }
    /// `dsc2_set_config` then `dsc2_enable` for engine `dsc` fed by OPP
    /// `opp`. An engine already clocked or forwarding for another OPP is
    /// refused (Linux asserts).
    pub fn start(&mut self, dsc: u8, opp: u8, r: &DscRegisters) -> Result<(), Error> {
        if dsc >= 6 || opp >= 6 {
            return Err(Error::Invalid);
        }
        let clocked = self.regs.read(self.engine(dsc, TOP_CONTROL))? & DSC_CLOCK_EN != 0;
        let forward = self.regs.read(self.at(FORWARD + u64::from(dsc)))?;
        let source = ((forward & FORWARD_OPP) >> 4) as u8;
        if (clocked || forward & FORWARD_EN != 0) && source != opp {
            return Err(Error::Busy);
        }
        for (reg, value) in engine_values(r) {
            self.regs.write(self.engine(dsc, reg), value)?;
        }
        self.regs
            .update(self.engine(dsc, TOP_CONTROL), DSC_CLOCK_EN, DSC_CLOCK_EN)?;
        self.regs.update(
            self.at(FORWARD + u64::from(dsc)),
            FORWARD_EN | FORWARD_OPP,
            FORWARD_EN | u32::from(opp) << 4,
        )
    }
    /// `dsc2_disconnect` then `dsc2_disable`.
    pub fn stop(&mut self, dsc: u8) -> Result<(), Error> {
        if dsc >= 6 {
            return Err(Error::Invalid);
        }
        self.regs
            .update(self.at(FORWARD + u64::from(dsc)), FORWARD_EN, 0)?;
        self.regs
            .update(self.engine(dsc, TOP_CONTROL), DSC_CLOCK_EN, 0)
    }
    /// `optc3_set_dsc_config` on OTG `otg`: the OPTC's DSC mode, bytes per
    /// pixel (U3.28) and slice width, then V_SYNC mode 0. `None` disables.
    pub fn optc(&mut self, otg: u8, r: Option<&DscRegisters>) -> Result<(), Error> {
        if otg >= 6 {
            return Err(Error::Invalid);
        }
        let dcn2 = self.dcn2;
        let odm = |reg: u64| dcn2 + (reg + u64::from(otg) * ODM_STRIDE) * 4;
        let (mode, bytes, width) = r.map_or((0, 0, 0), |r| {
            (optc_mode(r), r.bytes_per_pixel, r.slice_width)
        });
        self.regs.update(
            odm(OPTC_DATA_FORMAT_CONTROL),
            OPTC_DSC_MODE,
            mode << OPTC_DSC_MODE.trailing_zeros(),
        )?;
        self.regs
            .write(odm(OPTC_BYTES_PER_PIXEL), bytes & 0x7fff_ffff)?;
        self.regs.update(
            odm(OPTC_WIDTH_CONTROL),
            OPTC_DSC_SLICE_WIDTH,
            width << OPTC_DSC_SLICE_WIDTH.trailing_zeros(),
        )?;
        let vsync = self.at(OTG_V_SYNC_A_CNTL + u64::from(otg) * OTG_STRIDE);
        self.regs.update(vsync, OTG_V_SYNC_MODE, 0)
    }
    /// `enc3_dp_set_dsc_config` on frontend `fe`. `None` disables.
    pub fn encoder(&mut self, fe: u8, r: Option<&DscRegisters>) -> Result<(), Error> {
        if fe >= 6 {
            return Err(Error::Invalid);
        }
        let (mode, bytes, width) = r.map_or((0, 0, 0), |r| {
            (optc_mode(r), r.bytes_per_pixel, r.slice_width)
        });
        self.regs.update(
            self.dio(fe, DP_DSC_CNTL),
            DP_DSC_MODE | DP_DSC_SLICE_WIDTH,
            mode | width << DP_DSC_SLICE_WIDTH.trailing_zeros(),
        )?;
        self.regs.write(self.dio(fe, DP_DSC_BYTES_PER_PIXEL), bytes)
    }
    /// `vpg3_update_generic_info_packet(index, immediate)`.
    async fn vpg_packet(&mut self, fe: u8, index: u32, packet: &[u8; 36]) -> Result<(), Error> {
        let status = self.dio(fe, VPG_GENERIC_STATUS);
        if !self
            .regs
            .wait(status, VPG_GENERIC_CONFLICT_OCCURED, 0, 10, 50)
            .await?
        {
            return Err(Error::Hdmi(crate::amdgpu_dcn30_hdmi::Error::Conflict));
        }
        self.regs
            .update(status, VPG_GENERIC_CONFLICT_CLR, VPG_GENERIC_CONFLICT_CLR)?;
        self.regs.update(
            self.dio(fe, VPG_GENERIC_PACKET_ACCESS_CTRL),
            0xff,
            index * 9,
        )?;
        for word in packet.chunks_exact(4) {
            self.regs.write(
                self.dio(fe, VPG_GENERIC_PACKET_DATA),
                u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
            )?;
        }
        self.regs.update(
            self.dio(fe, VPG_GSP_IMMEDIATE_UPDATE_CTRL),
            1 << index,
            1 << index,
        )
    }
    /// `enc3_dp_set_dsc_pps_info_packet(enable)` on frontend `fe`: the
    /// 128-byte PPS in four 32-byte SDPs on VPG generic 11..14 (GSP11 in
    /// PPS mode), sent on line 2 of every frame with VBID[6] on line 3.
    pub async fn pps(&mut self, fe: u8, packed: Option<&[u8; 128]>) -> Result<(), Error> {
        if fe >= 6 {
            return Err(Error::Invalid);
        }
        let Some(packed) = packed else {
            self.regs
                .update(self.dio(fe, DP_GSP11_CNTL), DP_SEC_GSP11_ENABLE, 0)?;
            return self
                .regs
                .update(self.dio(fe, DP_SEC_CNTL2), DP_SEC_GSP11_PPS, 0);
        };
        self.regs.update(
            self.dio(fe, DP_SEC_CNTL2),
            DP_SEC_GSP11_PPS,
            DP_SEC_GSP11_PPS,
        )?;
        self.regs.update(
            self.dio(fe, AFMT_CNTL),
            AFMT_AUDIO_CLOCK_EN,
            AFMT_AUDIO_CLOCK_EN,
        )?;
        for i in 0..4u32 {
            let mut sdp = [0u8; 36];
            sdp[..4].copy_from_slice(&[0, SDP_TYPE_PPS, 127, 0]);
            let at = i as usize * 32;
            sdp[4..].copy_from_slice(&packed[at..at + 32]);
            self.vpg_packet(fe, 11 + i, &sdp).await?;
        }
        self.regs.update(
            self.dio(fe, DP_GSP11_CNTL),
            DP_SEC_GSP11_LINE_NUM,
            2 << DP_SEC_GSP11_LINE_NUM.trailing_zeros(),
        )?;
        self.regs.update(
            self.dio(fe, DP_MSA_VBID_MISC),
            DP_VBID6_LINE_REFERENCE | DP_VBID6_LINE_NUM,
            3 << DP_VBID6_LINE_NUM.trailing_zeros(),
        )?;
        self.regs.update(
            self.dio(fe, DP_GSP11_CNTL),
            DP_SEC_GSP11_ENABLE,
            DP_SEC_GSP11_ENABLE,
        )?;
        self.regs.update(
            self.dio(fe, DP_SEC_CNTL),
            DP_SEC_STREAM_ENABLE,
            DP_SEC_STREAM_ENABLE,
        )?;
        // Dynamic metadata keeps the secondary stream on regardless.
        if self.regs.read(self.dio(fe, DP_SEC_METADATA_TRANSMISSION))? & 1 != 0 {
            self.regs.update(
                self.dio(fe, DP_SEC_CNTL),
                DP_SEC_STREAM_ENABLE,
                DP_SEC_STREAM_ENABLE,
            )?;
        }
        Ok(())
    }
    /// `enc2_fec_set_ready` on `transmitter`'s link.
    pub fn fec_ready(&mut self, transmitter: u8, ready: bool) -> Result<(), Error> {
        if transmitter >= 6 {
            return Err(Error::Invalid);
        }
        self.regs.update(
            self.dio(transmitter, DP_DPHY_CNTL),
            DPHY_FEC_READY_SHADOW,
            if ready { DPHY_FEC_READY_SHADOW } else { 0 },
        )
    }
    /// `enc2_fec_set_enable` on `transmitter`'s link.
    pub fn fec_enable(&mut self, transmitter: u8, enable: bool) -> Result<(), Error> {
        if transmitter >= 6 {
            return Err(Error::Invalid);
        }
        self.regs.update(
            self.dio(transmitter, DP_DPHY_CNTL),
            DPHY_FEC_EN,
            if enable { DPHY_FEC_EN } else { 0 },
        )
    }
}

/// The sink's DSC and FEC capabilities, read before the link
/// (`dp_retrieve_lttpr_cap`'s neighbours in `detect_dp_sink_caps`).
pub async fn sink_caps<A: Aux + Send>(aux: &mut A) -> Result<([u8; 16], u8), Error> {
    let mut dsc = [0u8; 16];
    aux.read(DPCD_DSC_SUPPORT, &mut dsc).await?;
    let mut fec = [0u8];
    aux.read(DPCD_FEC_CAPABILITY, &mut fec).await?;
    Ok((dsc, fec[0]))
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_dsc_tests.rs"]
mod tests;
