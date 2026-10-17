//! Navi22 DCN3.0 HDMI TMDS stream: the DIG frontend/backend and VPG register
//! half of Linux's HDMI enable, around the VBIOS STREAM_SETUP and transmitter
//! tables that `amdgpu_navi22_bios` runs, plus the HDMI 2.0 decisions and the
//! sink-side SCDC protocol. Sequences follow
//! `dcn30_dio_stream_encoder.c::enc3_stream_encoder_hdmi_set_stream_attribute`,
//! `enc3_update_hdmi_info_packet`, `enc3_stream_encoder_update_hdmi_info_packets`
//! and `enc3_stream_encoder_stop_hdmi_info_packets`, `dcn30_vpg.c::
//! vpg3_update_generic_info_packet`, `dcn10_stream_encoder.c::
//! enc1_dig_connect_to_otg` and `dcn10_link_encoder.c::dcn10_link_encoder_setup`
//! / `connect_dig_be_to_fe`. Offsets and masks are `dcn_3_0_0_offset.h` /
//! `_sh_mask.h` at DCN base index 2; DIG frontends, backends and VPGs stride
//! 0x100.
//!
//! HDMI 2.0 (`link_dpms.c::enable_link_hdmi`, `link_ddc.c::write_scdc_data` /
//! `read_scdc_data`): a TMDS character clock above 340 MHz scrambles with a
//! 1/4-rate clock channel, and the sink is told over SCDC (I2C 0x54) before
//! the transmitter starts; a sink declaring LTE_340Mcsc_scramble scrambles
//! below it too. On the way down `link_set_dpms_off` returns an SCDC sink to
//! legacy TMDS ([`write_scdc_legacy`]). Linux's encoder switches at >= 340 MHz
//! but tells the sink only at > 340 MHz; both use > here, as the Navi48 path
//! does, so source and sink never disagree.
//!
//! Output formats follow amdgpu_dm (`convert_color_depth_from_display_info`,
//! `create_validate_stream_for_sink`'s 2-bpc step-down and 4:2:0 retry)
//! against `dcn10_link_encoder_validate_hdmi_output` with DCN3.0's
//! `link_enc_feature` (12 bpc, 600 MHz, 4:2:0, HDMI_6GB_EN from the VBIOS
//! encoder caps): RGB at 8, 10 or 12 bpc up to `amdgpu.max_bpc`, YCbCr 4:2:0
//! (8 bpc, BT.709) for modes the sink takes only that way or that fit no RGB
//! depth. The pixel-path half (FMT, OTG, MPC OCSC, DPG black) is
//! [`Formatter`].
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn30_dp::Aux, amdgpu_dcn_profile::Profile, amdgpu_dml::Timing,
    amdgpu_navi22_modeset::Error as LinkError,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[path = "amdgpu_dcn30_hdmi_format.rs"]
mod format;
pub use format::Formatter;

// linux-ctx: hdr=dcn seg=2
// linux: mmDIG1_DIG_FE_CNTL - mmDIG0_DIG_FE_CNTL
const STRIDE: u64 = 0x100;
// VPG instance (per stream frontend).
// linux: mmVPG0_VPG_GENERIC_PACKET_ACCESS_CTRL
const VPG_GENERIC_PACKET_ACCESS_CTRL: u64 = 0x2068;
// linux: mmVPG0_VPG_GENERIC_PACKET_DATA
const VPG_GENERIC_PACKET_DATA: u64 = 0x2069;
// linux: mmVPG0_VPG_GSP_IMMEDIATE_UPDATE_CTRL
const VPG_GSP_IMMEDIATE_UPDATE_CTRL: u64 = 0x206b;
// linux: mmVPG0_VPG_GENERIC_STATUS
const VPG_GENERIC_STATUS: u64 = 0x206c;
// DIG frontend.
// linux: mmDIG0_DIG_FE_CNTL
const DIG_FE_CNTL: u64 = 0x208b;
// linux: mmDIG0_HDMI_CONTROL
const HDMI_CONTROL: u64 = 0x2093;
// linux: mmDIG0_HDMI_VBI_PACKET_CONTROL
const HDMI_VBI_PACKET_CONTROL: u64 = 0x2097;
// linux: mmDIG0_HDMI_GENERIC_PACKET_CONTROL0
const HDMI_GENERIC_PACKET_CONTROL0: u64 = 0x209a;
// linux: mmDIG0_HDMI_GC
const HDMI_GC: u64 = 0x209d;
/// `HDMI_GENERIC_PACKET_CONTROL1..4`: GENERIC0/1, 2/3, 4/5 and 6/7 lines.
// linux: mmDIG0_HDMI_GENERIC_PACKET_CONTROL1; mmDIG0_HDMI_GENERIC_PACKET_CONTROL2; mmDIG0_HDMI_GENERIC_PACKET_CONTROL3; mmDIG0_HDMI_GENERIC_PACKET_CONTROL4
const HDMI_GENERIC_PACKET_LINES: [u64; 4] = [0x209e, 0x209f, 0x20a0, 0x20a1];
// linux: mmDIG0_HDMI_DB_CONTROL
const HDMI_DB_CONTROL: u64 = 0x20a6;
// linux: mmDIG0_AFMT_CNTL
const AFMT_CNTL: u64 = 0x20af;
// DIG backend.
const DIG_BE_CNTL: u64 = 0x20b0; // linux: mmDIG0_DIG_BE_CNTL
const DIG_BE_EN_CNTL: u64 = 0x20b1; // linux: mmDIG0_DIG_BE_EN_CNTL
const LAST_REG: u32 = (DIG_BE_EN_CNTL + 5 * STRIDE) as u32; // linux: mmDIG5_DIG_BE_EN_CNTL

// linux-ctx: reset
// linux: DIG0_DIG_FE_CNTL__DIG_SOURCE_SELECT_MASK
const DIG_SOURCE_SELECT: u32 = 0x7;
// linux: DIG0_DIG_FE_CNTL__DIG_STEREOSYNC_SELECT_MASK
const DIG_STEREOSYNC_SELECT: u32 = 0x70;
// linux: DIG0_DIG_FE_CNTL__DIG_STEREOSYNC_GATE_EN_MASK
const DIG_STEREOSYNC_GATE_EN: u32 = 1 << 8;
// linux: DIG0_DIG_FE_CNTL__TMDS_PIXEL_ENCODING_MASK
const TMDS_PIXEL_ENCODING: u32 = 1 << 28;
// linux: DIG0_DIG_FE_CNTL__TMDS_COLOR_FORMAT_MASK
const TMDS_COLOR_FORMAT: u32 = 0xc000_0000;
// linux: DIG0_HDMI_CONTROL__HDMI_KEEPOUT_MODE_MASK
const HDMI_KEEPOUT_MODE: u32 = 1 << 0;
// linux: DIG0_HDMI_CONTROL__HDMI_DATA_SCRAMBLE_EN_MASK
const HDMI_DATA_SCRAMBLE_EN: u32 = 1 << 1;
// linux: DIG0_HDMI_CONTROL__HDMI_CLOCK_CHANNEL_RATE_MASK
const HDMI_CLOCK_CHANNEL_RATE: u32 = 1 << 2;
// linux: DIG0_HDMI_CONTROL__HDMI_NO_EXTRA_NULL_PACKET_FILLED_MASK
const HDMI_NO_EXTRA_NULL_PACKET_FILLED: u32 = 1 << 3;
// linux: DIG0_HDMI_CONTROL__HDMI_PACKET_GEN_VERSION_MASK
const HDMI_PACKET_GEN_VERSION: u32 = 1 << 4;
// linux: DIG0_HDMI_CONTROL__HDMI_DEEP_COLOR_ENABLE_MASK
const HDMI_DEEP_COLOR_ENABLE: u32 = 1 << 24;
// linux: DIG0_HDMI_CONTROL__HDMI_DEEP_COLOR_DEPTH_MASK
const HDMI_DEEP_COLOR_DEPTH: u32 = 0x3000_0000;
// linux: DIG0_HDMI_VBI_PACKET_CONTROL__HDMI_NULL_SEND_MASK
const HDMI_NULL_SEND: u32 = 1 << 0;
// linux: DIG0_HDMI_VBI_PACKET_CONTROL__HDMI_GC_SEND_MASK
const HDMI_GC_SEND: u32 = 1 << 4;
// linux: DIG0_HDMI_VBI_PACKET_CONTROL__HDMI_GC_CONT_MASK
const HDMI_GC_CONT: u32 = 1 << 5;
// linux: DIG0_HDMI_VBI_PACKET_CONTROL__HDMI_ACP_SEND_MASK
const HDMI_ACP_SEND: u32 = 1 << 12;
// linux: DIG0_HDMI_GC__HDMI_GC_AVMUTE_MASK
const HDMI_GC_AVMUTE: u32 = 1 << 0;
// linux: DIG0_HDMI_DB_CONTROL__HDMI_DB_DISABLE_MASK
const HDMI_DB_DISABLE: u32 = 1 << 12;
// linux: DIG0_AFMT_CNTL__AFMT_AUDIO_CLOCK_EN_MASK
const AFMT_AUDIO_CLOCK_EN: u32 = 1 << 0;
// linux: VPG0_VPG_GENERIC_STATUS__VPG_GENERIC_CONFLICT_OCCURED_MASK
const VPG_GENERIC_CONFLICT_OCCURED: u32 = 1 << 1;
// linux: VPG0_VPG_GENERIC_STATUS__VPG_GENERIC_CONFLICT_CLR_MASK
const VPG_GENERIC_CONFLICT_CLR: u32 = 1 << 4;
// linux: VPG0_VPG_GENERIC_PACKET_ACCESS_CTRL__VPG_GENERIC_DATA_INDEX_MASK
const VPG_GENERIC_DATA_INDEX: u32 = 0xff;
// linux: DIG0_DIG_BE_CNTL__DIG_FE_SOURCE_SELECT_MASK
const DIG_FE_SOURCE_SELECT: u32 = 0x7f00;
// linux: DIG0_DIG_BE_CNTL__DIG_MODE_MASK
const DIG_MODE: u32 = 0x0007_0000;
// linux: DIG0_DIG_BE_EN_CNTL__DIG_ENABLE_MASK
const DIG_ENABLE: u32 = 1 << 0;
/// `enc3_update_hdmi_info_packet` sends on line 2.
// linux: n/a (literal `line = 2` in dcn30_dio_stream_encoder.c:enc3_update_hdmi_info_packet)
const INFO_PACKET_LINE: u32 = 2;
/// The highest TMDS character rate without scrambling
/// (`HDMI_CLOCK_CHANNEL_RATE_MORE_340M`).
// linux: n/a (HDMI_CLOCK_CHANNEL_RATE_MORE_340M, local #define in dcn30_dio_stream_encoder.c)
pub const TMDS_SCRAMBLE_KHZ: u32 = 340_000;
/// DCN3.0 `link_enc_feature.max_hdmi_pixel_clock`.
// linux: n/a (max_hdmi_pixel_clock = 600000, literal in dcn30_resource.c:link_enc_feature)
pub const TMDS_MAX_KHZ: u32 = 600_000;
/// `TMDS_MIN_PIXEL_CLOCK`.
pub const TMDS_MIN_KHZ: u32 = 25_000; // linux: TMDS_MIN_PIXEL_CLOCK
/// Without HDMI_6GB_EN `dcn10_link_encoder_validate_hdmi_output` refuses a
/// character clock of 300 MHz and up.
// linux: n/a (adjusted_pix_clk_100hz >= 3000000, literal in dcn10_link_encoder.c:dcn10_link_encoder_validate_hdmi_output)
pub const TMDS_NO_6G_KHZ: u32 = 300_000;
/// `enc3_stream_encoder_update_hdmi_info_packets`' packets in its order:
/// AVI (0), HF-VSIF (5), gamut (2), vendor (1), SPD (3), HDR (4), VTEM (6).
const PACKET_ORDER: [u32; 7] = [0, 5, 2, 1, 3, 4, 6];
// linux: n/a (packet_index 0, literal in dcn30_dio_stream_encoder.c:enc3_stream_encoder_update_hdmi_info_packets)
const PACKET_AVI: u32 = 0;
// linux: n/a (packet_index 1, literal in dcn30_dio_stream_encoder.c:enc3_stream_encoder_update_hdmi_info_packets)
const PACKET_VENDOR: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    DeviceGone,
    /// The backend already drives a link it did not get from this owner.
    Busy,
    /// The VPG reported a GSP memory conflict that never cleared.
    Conflict,
    /// An SCDC transaction to a sink that must scramble failed, or the DDC
    /// channel has no SCDC (a DP-only AUX).
    Scdc,
    /// A memory power state never settled (`REG_WAIT` bound).
    Timeout,
}

/// HDMI 2.0 SCDC registers (`dc_hdmi_types.h`).
pub mod scdc {
    /// The sink's 7-bit I2C address.
    // linux: n/a (HDMI_SCDC_ADDRESS in dc_hdmi_types.h, not in the checker's sets)
    pub const ADDRESS: u8 = 0x54;
    pub const SINK_VERSION: u8 = 0x01; // linux: SCDC_SINK_VERSION
    pub const SOURCE_VERSION: u8 = 0x02; // linux: SCDC_SOURCE_VERSION
    pub const TMDS_CONFIG: u8 = 0x20; // linux: SCDC_TMDS_CONFIG
    pub const SCRAMBLER_STATUS: u8 = 0x21; // linux: SCDC_SCRAMBLER_STATUS
    pub const STATUS_FLAGS: u8 = 0x40; // linux: SCDC_STATUS_FLAGS_0
    /// TMDS_Config: Scrambling_Enable and TMDS_Bit_Clock_Ratio (1/40).
    pub const SCRAMBLING_ENABLE: u8 = 1 << 0; // linux: SCDC_SCRAMBLING_ENABLE
    pub const BIT_CLOCK_RATIO_40: u8 = 1 << 1; // linux: SCDC_TMDS_BIT_CLOCK_RATIO_BY_40
}

/// Bits per component on an HDMI stream (`display_color_depth`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Depth {
    Bpc8,
    Bpc10,
    Bpc12,
}
impl Depth {
    pub fn bpc(self) -> u8 {
        match self {
            Self::Bpc8 => 8,
            Self::Bpc10 => 10,
            Self::Bpc12 => 12,
        }
    }
    /// HDMI_DEEP_COLOR_DEPTH and PHYPLL DCCG_DEEP_COLOR_CNTL: 0, 1 or 2.
    pub fn code(self) -> u32 {
        match self {
            Self::Bpc8 => 0,
            Self::Bpc10 => 1,
            Self::Bpc12 => 2,
        }
    }
    /// `dcn3_get_pix_clk_dividers`' HDMI deep-colour scaling, in 100 Hz:
    /// x5/4 or x6/4, truncated (the PLL target, `actual_pix_clk_100hz`).
    pub fn character_100hz(self, pixel_khz: u32) -> u64 {
        let p = u64::from(pixel_khz) * 10;
        match self {
            Self::Bpc8 => p,
            Self::Bpc10 => (p * 5) >> 2,
            Self::Bpc12 => (p * 6) >> 2,
        }
    }
    /// The TMDS character clock in kHz (`phy_pix_clk`), 0 if it overflows.
    pub fn character_khz(self, pixel_khz: u32) -> u32 {
        u32::try_from(self.character_100hz(pixel_khz) / 10).unwrap_or(0)
    }
}

/// The output format of one HDMI stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub depth: Depth,
    /// YCbCr 4:2:0 (BT.709, `COLOR_SPACE_YCBCR709`), else RGB.
    pub ycbcr420: bool,
    /// RGB limited range (`COLOR_SPACE_SRGB_LIMITED`, "Broadcast RGB"
    /// Limited); never set with 4:2:0.
    pub limited: bool,
}
impl Format {
    pub const RGB8: Self = Self {
        depth: Depth::Bpc8,
        ycbcr420: false,
        limited: false,
    };
}

/// The board's ceilings on an HDMI character clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The VBIOS encoder caps' HDMI6Gbps_EN; Linux keeps 1 without a record.
    pub hdmi6g: bool,
    /// DML30's `min(600, PHYCLK)` HDMI output bandwidth bound, in kHz.
    pub max_phy_khz: u32,
}
impl Limits {
    pub const DEFAULT: Self = Self {
        hdmi6g: true,
        max_phy_khz: TMDS_MAX_KHZ,
    };
    fn max_khz(self) -> u32 {
        let board = if self.hdmi6g {
            TMDS_MAX_KHZ
        } else {
            TMDS_NO_6G_KHZ - 1
        };
        board.min(self.max_phy_khz)
    }
}

/// How the sink is told to descramble: `write_scdc_data`'s TMDS_Config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scramble {
    /// Legacy TMDS (TMDS_Config 0).
    Off,
    /// LTE_340MCSC_SCRAMBLE at or below 340 MHz: scrambled, clock channel at
    /// the character rate (TMDS_Config 1).
    LowRate,
    /// Above 340 MHz: scrambled, 1/4-rate clock channel (TMDS_Config 3).
    Above340,
}
impl Scramble {
    pub fn tmds_config(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::LowRate => scdc::SCRAMBLING_ENABLE,
            Self::Above340 => scdc::SCRAMBLING_ENABLE | scdc::BIT_CLOCK_RATIO_40,
        }
    }
}

/// Everything one HDMI/DVI stream needs beyond its timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream {
    pub format: Format,
    /// The pixel clock the TMDS link carries (`requested_pix_clk`): the
    /// timing's, halved for 4:2:0's two pixels per container.
    pub pixel_khz: u32,
    /// The SetPixelClock target (`actual_pix_clk_100hz`).
    pub character_100hz: u32,
    /// The TMDS character clock (`phy_pix_clk`): STREAM_SETUP, the
    /// transmitter and the scrambling decision take it.
    pub character_khz: u32,
    pub scramble: Scramble,
    /// The sink declared SCDC (`edid_caps.scdc_present`).
    pub scdc: bool,
    /// The AVI InfoFrame; None for a DVI sink (no data islands).
    pub avi: Option<[u8; 36]>,
    /// The HDMI 1.4b vendor InfoFrame for a 4K HDMI VIC.
    pub vendor: Option<[u8; 36]>,
}

/// HF-VSDB/HF-SCDB LTE_340Mcsc_scramble, as DRM's
/// `drm_parse_hdmi_forum_scds` sets `scrambling.low_rates`: SCDC present,
/// a non-zero Max_TMDS_Character_Rate, and flag bit 3.
fn low_rate_scrambling(edid: &[u8]) -> bool {
    use narf_edid::cta861::{CtaExtension, DataBlock};
    edid.chunks_exact(128).skip(1).any(|block| {
        CtaExtension::parse(block).is_ok_and(|cta| {
            cta.data_blocks.iter().any(|db| {
                let forum = match db {
                    DataBlock::Vendor(v) if v.is_hdmi_forum() && v.payload.len() >= 7 => {
                        v.payload.get(3..)
                    }
                    DataBlock::Extended {
                        // linux: n/a (CTA_EXT_DB_HF_SCDB, local #define in drm_edid.c)
                        ext_tag: 0x79,
                        payload,
                    } if payload.len() >= 6 => payload.get(2..),
                    _ => None,
                };
                matches!(forum, Some(&[_, rate, flags, ..])
                    if rate != 0 && flags & 0x80 != 0 && flags & 0x08 != 0)
            })
        })
    })
}

/// `t` as DRM's mode matchers take it.
fn edid_mode(t: &Timing) -> narf_edid::modes::FixedMode {
    let field = |active: u32, front: u32, sync: u32, total: u32| {
        let at = |x: u32| u16::try_from(x).unwrap_or(u16::MAX);
        [
            at(active),
            at(active + front),
            at(active + front + sync),
            at(total),
        ]
    };
    narf_edid::modes::progressive(
        t.pixel_clock_khz,
        field(t.h_active, t.h_front_porch, t.h_sync_width, t.h_total),
        field(t.v_active, t.v_front_porch, t.v_sync_width, t.v_total),
        t.h_sync_positive,
        t.v_sync_positive,
    )
}

type Caps = crate::amdgpu_navi48_boot::HdmiCaps;

/// Whether the sink and this board carry a TMDS character clock: the
/// encoder's range, then the EDID's ceiling (DRM's `max_tmds_clock`: the
/// HF rate when it declares more than 340 MHz, else the VSDB's) and, above
/// 340 MHz, SCDC (DRM's scrambling-support rule).
fn fits(caps: &Caps, khz: u32, limits: Limits) -> bool {
    if !(TMDS_MIN_KHZ..=limits.max_khz()).contains(&khz) {
        return false;
    }
    if khz <= TMDS_SCRAMBLE_KHZ {
        let max = if caps.forum_max_khz > TMDS_SCRAMBLE_KHZ {
            caps.forum_max_khz
        } else {
            caps.vsdb_max_khz
        };
        return max == 0 || khz <= max;
    }
    caps.scdc && khz <= caps.forum_max_khz
}

/// The format amdgpu_dm would drive `t` with on this sink: a mode the sink
/// takes only as 4:2:0 (`drm_mode_is_420_only`) as 4:2:0; otherwise RGB at
/// the deepest declared depth up to `max_bpc` that fits, stepping down by 2
/// bpc; failing that 4:2:0 where the sink also takes it
/// (`drm_mode_is_420_also`). 4:2:0 is 8 bpc. A DVI sink gets 8-bpc RGB.
fn choose(caps: &Caps, t: &Timing, max_bpc: u8, limits: Limits) -> Option<(Depth, bool)> {
    let vic = narf_edid::modes::match_cea_mode(edid_mode(t));
    let listed = |map: [u64; 4]| vic != 0 && map[usize::from(vic / 64)] & 1 << (vic % 64) != 0;
    let fits_420 = || caps.hdmi && fits(caps, t.pixel_clock_khz / 2, limits);
    if caps.hdmi && listed(caps.y420_only) {
        return fits_420().then_some((Depth::Bpc8, true));
    }
    let rgb = [
        (Depth::Bpc12, caps.hdmi && caps.dc36),
        (Depth::Bpc10, caps.hdmi && caps.dc30),
        (Depth::Bpc8, true),
    ];
    let deepest = rgb.into_iter().find(|&(depth, declared)| {
        declared
            && depth.bpc() <= max_bpc.max(8)
            && fits(caps, depth.character_khz(t.pixel_clock_khz), limits)
    });
    if let Some((depth, _)) = deepest {
        return Some((depth, false));
    }
    (listed(caps.y420_also) && fits_420()).then_some((Depth::Bpc8, true))
}

/// The stream amdgpu_dm and DC would build for `t` on the sink whose whole
/// EDID is `edid`: the format ([`choose`]), its clocks, the scrambling
/// decision, and the AVI (CTA VIC, Q for RGB) and HDMI vendor InfoFrames.
/// `limited` is "Broadcast RGB" Limited. None when nothing fits.
pub fn stream_for(
    edid: &[u8],
    t: &Timing,
    max_bpc: u8,
    limited: bool,
    limits: Limits,
) -> Option<Stream> {
    use crate::amdgpu_navi48_boot as navi48;
    let caps = navi48::hdmi_caps(edid);
    let (depth, ycbcr420) = choose(&caps, t, max_bpc, limits)?;
    let pixel_khz = t.pixel_clock_khz >> u32::from(ycbcr420);
    let character_100hz = u32::try_from(depth.character_100hz(pixel_khz)).ok()?;
    let character_khz = character_100hz / 10;
    let scramble = if character_khz > TMDS_SCRAMBLE_KHZ {
        Scramble::Above340
    } else if caps.hdmi && caps.scdc && low_rate_scrambling(edid) {
        Scramble::LowRate
    } else {
        Scramble::Off
    };
    let limited = limited && !ycbcr420 && caps.hdmi;
    let avi = navi48::hdmi_avi(caps, t);
    Some(Stream {
        format: Format {
            depth,
            ycbcr420,
            limited,
        },
        pixel_khz,
        character_100hz,
        character_khz,
        scramble,
        scdc: caps.hdmi && caps.scdc,
        avi: caps
            .hdmi
            .then(|| crate::amdgpu_dcn401_otg::avi_infoframe(t, avi, limited, ycbcr420)),
        vendor: caps
            .hdmi
            .then(|| crate::amdgpu_dcn401_otg::vendor_infoframe(t, avi))
            .flatten(),
    })
}

/// `write_scdc_data` before the TMDS link starts: nothing for a sink
/// without SCDC; else read Sink_Version, answer version 1 with
/// Source_Version 1, then write TMDS_Config. Linux (`link_ddc.c`) checks
/// none of these transfers: a failed Sink_Version read leaves its
/// `sink_version = 0` (so no Source_Version) and TMDS_Config is written
/// regardless, as here. A scrambled stream the sink was not told about
/// cannot display, so a failed TMDS_Config write fails the link; the legacy
/// (unscrambled) write's result is ignored, as in Linux.
pub async fn write_scdc_data<A: Aux>(ddc: &mut A, stream: &Stream) -> Result<(), Error> {
    if !stream.scdc {
        return Ok(());
    }
    let config = stream.scramble.tmds_config();
    if ddc.scdc_read(scdc::SINK_VERSION).await.unwrap_or(0) == 1 {
        let _ = ddc.scdc_write(scdc::SOURCE_VERSION, 1).await;
    }
    let result: Result<(), LinkError> = ddc.scdc_write(scdc::TMDS_CONFIG, config).await;
    match result {
        Err(_) if config != 0 => Err(Error::Scdc),
        _ => Ok(()),
    }
}

/// `link_set_dpms_off`'s `write_scdc_data(165000, false)`: tell an SCDC sink
/// it is back on legacy TMDS, best effort (a sink already unplugged NACKs).
/// The link owner calls this on disable and on unplug, before the
/// transmitter stops.
pub async fn write_scdc_legacy<A: Aux>(ddc: &mut A, scdc_present: bool) {
    if !scdc_present {
        return;
    }
    if ddc.scdc_read(scdc::SINK_VERSION).await == Ok(1) {
        let _ = ddc.scdc_write(scdc::SOURCE_VERSION, 1).await;
    }
    let _ = ddc.scdc_write(scdc::TMDS_CONFIG, 0).await;
}

/// What `read_scdc_data` reads once the transmitter runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScdcStatus {
    pub tmds_config: u8,
    /// Scrambling_Status (bit 0) and the status flags (clock detected,
    /// channel locks), read only when TMDS_Config says scrambling.
    pub scrambler_status: Option<u8>,
    pub status_flags: Option<u8>,
}
/// `read_scdc_data` after `enable_tmds_link_output`: diagnostics only.
pub async fn read_scdc_data<A: Aux>(ddc: &mut A, stream: &Stream) -> Option<ScdcStatus> {
    if !stream.scdc {
        return None;
    }
    let tmds_config = ddc.scdc_read(scdc::TMDS_CONFIG).await.ok()?;
    let mut status = ScdcStatus {
        tmds_config,
        ..ScdcStatus::default()
    };
    if tmds_config & scdc::SCRAMBLING_ENABLE != 0 {
        status.scrambler_status = ddc.scdc_read(scdc::SCRAMBLER_STATUS).await.ok();
        status.status_flags = ddc.scdc_read(scdc::STATUS_FLAGS).await.ok();
    }
    Some(status)
}

pub(crate) trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: constructor bounds the DCN bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this owner holds the frontend/backend.
        unsafe { self.regs.write32(self.base + reg * 4, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}

#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub(crate) io: I,
    authority: Cap<BusDeviceCap, Write>,
    dig: u8,
    transmitter: u8,
}
impl<I: Io> Engine<I> {
    pub(crate) fn new_with(
        io: I,
        authority: Cap<BusDeviceCap, Write>,
        dig: u8,
        transmitter: u8,
    ) -> Self {
        Self {
            io,
            authority,
            dig,
            transmitter,
        }
    }
    fn fe(&self, reg: u64) -> u64 {
        reg + u64::from(self.dig) * STRIDE
    }
    fn be(&self, reg: u64) -> u64 {
        reg + u64::from(self.transmitter) * STRIDE
    }
    fn read(&mut self, reg: u64) -> Result<u32, Error> {
        let io = &mut self.io;
        let value = self
            .authority
            .invoke(Op(|| io.read(reg)))
            .map_err(|_| Error::Revoked)?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
    fn write(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| io.write(reg, value)))
            .map_err(|_| Error::Revoked)
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(reg)?;
        self.write(reg, (old & !mask) | (value & mask))
    }
    /// The backend must be idle before this owner programs it.
    pub(crate) fn check_idle(&mut self) -> Result<(), Error> {
        if self.read(self.be(DIG_BE_EN_CNTL))? & DIG_ENABLE != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    /// `enc1_dig_connect_to_otg`: the frontend takes its pixels from `otg`.
    pub(crate) fn connect_to_otg(&mut self, otg: u8) -> Result<(), Error> {
        // linux: n/a (NARF bound: DCN30 has six OTGs)
        if otg >= 6 {
            return Err(Error::Invalid);
        }
        self.update(self.fe(DIG_FE_CNTL), DIG_SOURCE_SELECT, u32::from(otg))
    }
    /// `enc1_setup_stereo_sync(otg, false)`: stereo sync from `otg`, gated.
    pub(crate) fn setup_stereo_sync(&mut self, otg: u8) -> Result<(), Error> {
        // linux: n/a (NARF bound: DCN30 has six OTGs)
        if otg >= 6 {
            return Err(Error::Invalid);
        }
        self.update(
            self.fe(DIG_FE_CNTL),
            DIG_STEREOSYNC_SELECT | DIG_STEREOSYNC_GATE_EN,
            // linux-lit: 4=DIG0_DIG_FE_CNTL__DIG_STEREOSYNC_SELECT__SHIFT
            u32::from(otg) << 4 | DIG_STEREOSYNC_GATE_EN,
        )
    }
    /// `dcn10_link_encoder_setup`: the backend's DIG_MODE for the signal.
    pub(crate) fn setup(&mut self, mode: DigMode) -> Result<(), Error> {
        // linux-lit: 16=DIG0_DIG_BE_CNTL__DIG_MODE__SHIFT
        self.update(self.be(DIG_BE_CNTL), DIG_MODE, (mode as u32) << 16)
    }
    /// `dcn10_link_encoder_connect_dig_be_to_fe`: add or drop this frontend
    /// in the backend's one-hot source mask, keeping any other frontend.
    pub(crate) fn connect_be_to_fe(&mut self, connect: bool) -> Result<(), Error> {
        let be = self.read(self.be(DIG_BE_CNTL))?;
        // linux-lit: 8=DIG0_DIG_BE_CNTL__DIG_FE_SOURCE_SELECT__SHIFT
        let source = 1 << (8 + u32::from(self.dig));
        let field = if connect {
            (be & DIG_FE_SOURCE_SELECT) | source
        } else {
            be & DIG_FE_SOURCE_SELECT & !source
        };
        self.update(self.be(DIG_BE_CNTL), DIG_FE_SOURCE_SELECT, field)
    }
    /// `enc1_stream_encoder_set_avmute`.
    pub(crate) fn set_avmute(&mut self, mute: bool) -> Result<(), Error> {
        self.update(
            self.fe(HDMI_GC),
            HDMI_GC_AVMUTE,
            if mute { HDMI_GC_AVMUTE } else { 0 },
        )
    }
    /// The register half of `enc3_stream_encoder_hdmi_set_stream_attribute`
    /// after the VBIOS STREAM_SETUP, for 8-bpc RGB without scrambling.
    pub(crate) fn stream_attribute(&mut self, character_khz: u32) -> Result<(), Error> {
        if character_khz >= TMDS_SCRAMBLE_KHZ {
            return Err(Error::Unsupported);
        }
        self.hdmi_stream_attribute(Format::RGB8, character_khz, Scramble::Off)
    }
    /// `enc3_stream_encoder_hdmi_set_stream_attribute`'s register half:
    /// `enc1_stream_encoder_set_stream_attribute_helper` (RGB and 4:2:0 both
    /// TMDS_PIXEL_ENCODING 0), the HDMI engine reset to GEN v1, keepout and
    /// no extra NULL, then the deep-colour depth (enabled for every depth but
    /// 8 bpc), the scrambler (1/4-rate clock channel above 340 MHz, character
    /// rate for LTE_340MCSC), GC/NULL packets every frame, ACP off and AVMUTE
    /// released.
    pub(crate) fn hdmi_stream_attribute(
        &mut self,
        format: Format,
        character_khz: u32,
        scramble: Scramble,
    ) -> Result<(), Error> {
        if !(TMDS_MIN_KHZ..=TMDS_MAX_KHZ).contains(&character_khz)
            || (scramble == Scramble::Above340) != (character_khz > TMDS_SCRAMBLE_KHZ)
        {
            return Err(Error::Unsupported);
        }
        self.update(self.fe(DIG_FE_CNTL), TMDS_PIXEL_ENCODING, 0)?;
        self.update(self.fe(DIG_FE_CNTL), TMDS_COLOR_FORMAT, 0)?;
        self.update(
            self.fe(HDMI_CONTROL),
            HDMI_PACKET_GEN_VERSION
                | HDMI_KEEPOUT_MODE
                | HDMI_DEEP_COLOR_ENABLE
                | HDMI_DATA_SCRAMBLE_EN
                | HDMI_NO_EXTRA_NULL_PACKET_FILLED
                | HDMI_CLOCK_CHANNEL_RATE,
            HDMI_PACKET_GEN_VERSION | HDMI_KEEPOUT_MODE | HDMI_NO_EXTRA_NULL_PACKET_FILLED,
        )?;
        let code = format.depth.code();
        let enable = if code != 0 { HDMI_DEEP_COLOR_ENABLE } else { 0 };
        self.update(
            self.fe(HDMI_CONTROL),
            HDMI_DEEP_COLOR_DEPTH | HDMI_DEEP_COLOR_ENABLE,
            code << 28 | enable,
        )?;
        let scrambler = match scramble {
            Scramble::Off => None,
            Scramble::LowRate => Some(HDMI_DATA_SCRAMBLE_EN),
            Scramble::Above340 => Some(HDMI_DATA_SCRAMBLE_EN | HDMI_CLOCK_CHANNEL_RATE),
        };
        if let Some(bits) = scrambler {
            self.update(
                self.fe(HDMI_CONTROL),
                HDMI_DATA_SCRAMBLE_EN | HDMI_CLOCK_CHANNEL_RATE,
                bits,
            )?;
        }
        self.update(
            self.fe(HDMI_VBI_PACKET_CONTROL),
            HDMI_GC_CONT | HDMI_GC_SEND | HDMI_NULL_SEND,
            HDMI_GC_CONT | HDMI_GC_SEND | HDMI_NULL_SEND,
        )?;
        self.update(self.fe(HDMI_VBI_PACKET_CONTROL), HDMI_ACP_SEND, 0)?;
        self.update(self.fe(HDMI_GC), HDMI_GC_AVMUTE, 0)
    }
    /// `vpg3_update_generic_info_packet(index, packet, immediate)`.
    async fn vpg_packet(&mut self, index: u32, packet: &[u8; 36]) -> Result<(), Error> {
        let status = self.fe(VPG_GENERIC_STATUS);
        let mut clear = false;
        // linux: n/a (max_retries = 50, literal in dcn30_vpg.c:vpg3_update_generic_info_packet)
        for _ in 0..50 {
            if self.read(status)? & VPG_GENERIC_CONFLICT_OCCURED == 0 {
                clear = true;
                break;
            }
            // linux: n/a (REG_WAIT delay 10 us, literal in dcn30_vpg.c:vpg3_update_generic_info_packet)
            sleep_us(10).await;
        }
        // Linux's REG_WAIT only logs the timeout, then clears the conflict
        // and writes the packet anyway.
        if !clear {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 VPG {} GSP conflict did not clear; writing packet {index}",
                self.dig
            );
        }
        self.update(status, VPG_GENERIC_CONFLICT_CLR, VPG_GENERIC_CONFLICT_CLR)?;
        self.update(
            self.fe(VPG_GENERIC_PACKET_ACCESS_CTRL),
            VPG_GENERIC_DATA_INDEX,
            // linux: n/a (packet_index*9, literal in dcn30_vpg.c:vpg3_update_generic_info_packet)
            index * 9,
        )?;
        // HB0..HB3, then the first 32 SB bytes; the last four are never used.
        for word in packet.chunks_exact(4) {
            self.write(
                self.fe(VPG_GENERIC_PACKET_DATA),
                u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
            )?;
        }
        self.update(
            self.fe(VPG_GSP_IMMEDIATE_UPDATE_CTRL),
            1 << index,
            1 << index,
        )
    }
    /// `HDMI_GENERIC_PACKET_CONTROL0` CONT/SEND and the packet's line field.
    fn packet_control(&mut self, index: u32, send: bool) -> Result<(), Error> {
        // linux-lit: 0x3=DIG0_HDMI_GENERIC_PACKET_CONTROL0__HDMI_GENERIC0_SEND_MASK | DIG0_HDMI_GENERIC_PACKET_CONTROL0__HDMI_GENERIC0_CONT_MASK; 4=DIG0_HDMI_GENERIC_PACKET_CONTROL0__HDMI_GENERIC1_SEND__SHIFT
        let bits = 0x3 << (4 * index);
        self.update(
            self.fe(HDMI_GENERIC_PACKET_CONTROL0),
            bits,
            if send { bits } else { 0 },
        )?;
        let reg = HDMI_GENERIC_PACKET_LINES[(index / 2) as usize];
        // linux-lit: 16=DIG0_HDMI_GENERIC_PACKET_CONTROL1__HDMI_GENERIC1_LINE__SHIFT
        let shift = 16 * (index % 2);
        self.update(
            self.fe(reg),
            // linux-lit: 0xffff=DIG0_HDMI_GENERIC_PACKET_CONTROL1__HDMI_GENERIC0_LINE_MASK
            0xffff << shift,
            if send { INFO_PACKET_LINE << shift } else { 0 },
        )
    }
    /// `enc3_stream_encoder_update_hdmi_info_packets` with only the AVI
    /// InfoFrame valid.
    pub(crate) async fn info_packets(&mut self, avi: &[u8; 36]) -> Result<(), Error> {
        self.hdmi_info_packets(avi, None).await
    }
    /// `enc3_stream_encoder_update_hdmi_info_packets`: the AVI InfoFrame,
    /// and the HDMI vendor InfoFrame when there is one; every other managed
    /// packet off, in Linux's order.
    pub(crate) async fn hdmi_info_packets(
        &mut self,
        avi: &[u8; 36],
        vendor: Option<&[u8; 36]>,
    ) -> Result<(), Error> {
        if avi[0] != 0x82 || vendor.is_some_and(|v| v[0] != 0x81) {
            return Err(Error::Invalid);
        }
        self.update(self.fe(HDMI_DB_CONTROL), HDMI_DB_DISABLE, HDMI_DB_DISABLE)?;
        self.update(self.fe(AFMT_CNTL), AFMT_AUDIO_CLOCK_EN, AFMT_AUDIO_CLOCK_EN)?;
        for index in PACKET_ORDER {
            let packet = match index {
                PACKET_AVI => Some(avi),
                PACKET_VENDOR => vendor,
                _ => None,
            };
            if let Some(packet) = packet {
                self.vpg_packet(index, packet).await?;
            }
            self.packet_control(index, packet.is_some())?;
        }
        Ok(())
    }
    /// `enc3_stream_encoder_stop_hdmi_info_packets` for packets 0..7.
    pub(crate) fn stop_info_packets(&mut self) -> Result<(), Error> {
        self.write(self.fe(HDMI_GENERIC_PACKET_CONTROL0), 0)?;
        for reg in HDMI_GENERIC_PACKET_LINES {
            self.write(self.fe(reg), 0)?;
        }
        Ok(())
    }
}

/// `DIG_BE_CNTL.DIG_MODE` values `dcn10_link_encoder_setup` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigMode {
    /// `SIGNAL_TYPE_DISPLAY_PORT` (SST).
    // linux: n/a (DIG_MODE 0, literal in dcn10_link_encoder.c:dcn10_link_encoder_setup)
    DisplayPort = 0,
    /// `SIGNAL_TYPE_HDMI_TYPE_A`.
    Hdmi = 3, // linux: n/a (DIG_MODE 3, literal in dcn10_link_encoder.c:dcn10_link_encoder_setup)
}

/// One HDMI stream frontend `dig` routed to physical transmitter `transmitter`.
#[derive(Debug)]
pub struct Hdmi(Engine<Mmio>);
impl Hdmi {
    /// # Safety
    /// Caller exclusively owns DIG frontend `dig`, its VPG and backend
    /// `transmitter` for the object's lifetime, holds matching PCI authority
    /// and a permanent register mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        dig: u8,
        transmitter: u8,
    ) -> Result<Self, Error> {
        if Profile::resolve(gpu).map_err(|_| Error::Unsupported)? != Profile::Navi22 {
            return Err(Error::Unsupported);
        }
        // linux: n/a (NARF bound: six DIG frontends/backends)
        if dig >= 6 || transmitter >= 6 {
            return Err(Error::Invalid);
        }
        let base = Profile::Navi22
            .bank(gpu, 2, LAST_REG) // linux-lit: 2=mmDIG0_DIG_FE_CNTL_BASE_IDX
            .map_err(|_| Error::Unsupported)?;
        Ok(Self(Engine::new_with(
            Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base,
            },
            authority,
            dig,
            transmitter,
        )))
    }
    pub fn check_idle(&mut self) -> Result<(), Error> {
        self.0.check_idle()
    }
    pub fn connect_to_otg(&mut self, otg: u8) -> Result<(), Error> {
        self.0.connect_to_otg(otg)
    }
    pub fn setup(&mut self, mode: DigMode) -> Result<(), Error> {
        self.0.setup(mode)
    }
    pub fn setup_stereo_sync(&mut self, otg: u8) -> Result<(), Error> {
        self.0.setup_stereo_sync(otg)
    }
    pub fn connect_be_to_fe(&mut self, connect: bool) -> Result<(), Error> {
        self.0.connect_be_to_fe(connect)
    }
    pub fn set_avmute(&mut self, mute: bool) -> Result<(), Error> {
        self.0.set_avmute(mute)
    }
    pub fn stream_attribute(&mut self, character_khz: u32) -> Result<(), Error> {
        self.0.stream_attribute(character_khz)
    }
    /// [`Engine::hdmi_stream_attribute`] for `stream`.
    pub fn hdmi_stream_attribute(&mut self, stream: &Stream) -> Result<(), Error> {
        self.0
            .hdmi_stream_attribute(stream.format, stream.character_khz, stream.scramble)
    }
    pub async fn info_packets(&mut self, avi: &[u8; 36]) -> Result<(), Error> {
        self.0.info_packets(avi).await
    }
    /// The AVI and (when present) HDMI vendor InfoFrames of `stream`.
    pub async fn hdmi_info_packets(&mut self, stream: &Stream) -> Result<(), Error> {
        let avi = stream.avi.as_ref().ok_or(Error::Invalid)?;
        self.0.hdmi_info_packets(avi, stream.vendor.as_ref()).await
    }
    pub fn stop_info_packets(&mut self) -> Result<(), Error> {
        self.0.stop_info_packets()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_hdmi_tests.rs"]
mod tests;
