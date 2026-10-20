//! Linux's HDMI FRL capacity check (dml/dml1_frl_cap_chk.c), as
//! hpo_enc3_validate_hdmi_frl_output feeds it: whether `lanes` FRL lanes at
//! a nominal rate carry a timing with its audio, uncompressed
//! (dml1_frl_cap_chk_uncompressed) or as a DSC stream
//! (dml1_frl_cap_chk_compressed, with its CTA primary-format tribyte
//! targets), and the tribyte borrow mode, HCactive/HCblank targets and audio
//! packets per line the HPO FRL stream encoder then needs. `dsc_borrow` is
//! frl_modify_borrow_mode_for_dsc_padding, which hdmi_frl_decide_link_settings
//! applies to the decided link.
//!
//! The arithmetic is Linux's own, operation for operation: IEEE doubles,
//! with dml_max/dml_min/dml_floor/dml_ceil rounding through 32-bit floats as
//! dcn_bw_max2/min2/floor2/ceil2 do (the ceiling adding a double 0.99999 to
//! the float quotient). drivers/gpu/tests/dcn401_frl/check.sh verifies the
//! reference vectors against the Linux source compiled on the host.

/// TB_BORROWED_MAX, C_FRL_CB, TOLERANCE_FRL_BIT (ppm), ACR_RATE_MAX.
const TB_BORROWED_MAX: f64 = 400.0;
const C_FRL_CB: i32 = 510;
const TOLERANCE_FRL_BIT: i32 = 300;
const ACR_RATE_MAX: i32 = 1500;
const EPSILON: f64 = 0.01;
const DBL_EPSILON: f64 = f64::EPSILON;
const OVERHEAD_M: f64 = 0.003;
const TOLERANCE_PIXEL_CLOCK: f64 = 0.005;
const TOLERANCE_AUDIO_CLOCK: f64 = 1000.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrlEncoding {
    Rgb444,
    Ycbcr422,
    Ycbcr420,
}

/// get_audio_check of the sink's audio modes: packet type 2 (audio sample
/// packets), or 9 above 192 kHz; the highest sample rate; layout 1 for
/// more than two channels above 576 lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlAudio {
    pub packet_type: u8,
    pub max_rate_hz: u32,
    pub layout: u8,
}

/// The DSC side of a compressed stream, as hpo_fpu_enc3_validate_hdmi_frl_
/// output_timing fills it: slices, the slice width (rounded up, and even
/// for 4:2:0), the compressed bpp, the AVI VIC (an HDMI VIC mapped to its
/// CTA one) and the sink's DSC_All_bpp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlDsc {
    pub slices: u32,
    pub slice_width: u32,
    pub bpp_x16: u32,
    pub vic: u8,
    pub all_bpp: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlCapInput {
    pub lanes: u8,
    /// The nominal per-lane rate in Gbps: 3, 6, 8, 10 or 12.
    pub gbps: u8,
    pub pixel_clock_100hz: u32,
    pub h_active: u32,
    pub h_blank: u32,
    pub bpc: u8,
    pub encoding: FrlEncoding,
    pub audio: FrlAudio,
    /// A DSC stream: dml1_frl_cap_chk_compressed.
    pub dsc: Option<FrlDsc>,
}

/// FRL_BORROW_MODE_* (HDMI_TB_ENC_MODE.HDMI_BORROW_MODE). The uncompressed
/// check never chooses FROM_ACTIVE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrlBorrow {
    None = 0,
    FromActive = 1,
    FromBlank = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrlCap {
    Ok {
        audio_packets_line: u32,
        borrow: FrlBorrow,
        /// The compressed check's HCactive/HCblank tribyte targets; zero
        /// uncompressed, where Linux leaves them unset.
        hc_active: u32,
        hc_blank: u32,
    },
    AudioBandwidth,
    Borrow,
    MaxBorrow,
    Margin,
    UnsupportedAudio,
}
impl FrlCap {
    /// Linux's frl_cap_chk_result code.
    pub fn code(self) -> i32 {
        match self {
            Self::Ok { .. } => 0,
            Self::AudioBandwidth => -1,
            Self::Borrow => -2,
            Self::MaxBorrow => -3,
            Self::Margin => -4,
            Self::UnsupportedAudio => -1000,
        }
    }
}

// prim_format_444/422/420: (VIC, HCactive, HCblank) of the CTA formats
// whose compressed tribyte targets HDMI 2.1 fixes.
const PRIM_FORMAT_444: [(u8, u16, u16); 58] = [
    (64, 960, 360),
    (77, 960, 360),
    (63, 960, 140),
    (78, 960, 140),
    (93, 1920, 828),
    (103, 1920, 828),
    (94, 1920, 720),
    (104, 1920, 720),
    (95, 1920, 280),
    (105, 1920, 280),
    (114, 1920, 828),
    (116, 1920, 828),
    (96, 1920, 720),
    (106, 1920, 720),
    (97, 1920, 280),
    (107, 1920, 280),
    (117, 1920, 720),
    (119, 1920, 720),
    (118, 1920, 280),
    (120, 1920, 280),
    (98, 2048, 700),
    (99, 2048, 592),
    (100, 2048, 152),
    (115, 2048, 700),
    (101, 2048, 592),
    (102, 2048, 152),
    (218, 2048, 592),
    (219, 2048, 152),
    (121, 2560, 1188),
    (122, 2560, 1040),
    (123, 2560, 440),
    (124, 2560, 256),
    (125, 2560, 484),
    (126, 2307, 144),
    (127, 2560, 484),
    (193, 2334, 104),
    (194, 3840, 1660),
    (202, 3840, 1660),
    (195, 3840, 1560),
    (203, 3840, 1560),
    (196, 3840, 660),
    (204, 3840, 660),
    (197, 3142, 1292),
    (205, 3142, 1292),
    (198, 3142, 1180),
    (206, 3142, 1180),
    (199, 3182, 140),
    (207, 3182, 140),
    (200, 2680, 784),
    (208, 2680, 784),
    (201, 2600, 100),
    (209, 2600, 100),
    (210, 4854, 912),
    (211, 4827, 1536),
    (212, 4720, 128),
    (213, 4347, 756),
    (214, 4320, 1376),
    (215, 4187, 124),
];
const PRIM_FORMAT_422: [(u8, u16, u16); 60] = [
    (64, 960, 360),
    (77, 960, 360),
    (63, 960, 140),
    (78, 960, 140),
    (93, 1920, 828),
    (103, 1920, 828),
    (94, 1920, 720),
    (104, 1920, 720),
    (95, 1920, 280),
    (105, 1920, 280),
    (114, 1920, 828),
    (116, 1920, 828),
    (96, 1920, 720),
    (106, 1920, 720),
    (97, 1920, 280),
    (107, 1920, 280),
    (117, 1370, 104),
    (119, 1370, 104),
    (118, 1130, 104),
    (120, 1130, 104),
    (98, 2048, 700),
    (99, 2048, 592),
    (100, 2048, 152),
    (115, 2048, 700),
    (101, 2048, 592),
    (102, 2048, 152),
    (218, 2048, 592),
    (219, 2048, 152),
    (121, 2560, 1188),
    (122, 2560, 1040),
    (123, 2560, 440),
    (124, 2560, 256),
    (125, 2560, 484),
    (126, 2307, 144),
    (127, 2560, 484),
    (193, 2334, 104),
    (194, 2460, 816),
    (202, 2460, 816),
    (195, 2460, 732),
    (203, 2460, 732),
    (196, 2360, 144),
    (204, 2360, 144),
    (197, 2460, 816),
    (205, 2460, 816),
    (198, 2460, 732),
    (206, 2460, 732),
    (199, 2380, 116),
    (207, 2380, 116),
    (200, 2680, 784),
    (208, 2680, 784),
    (201, 2600, 100),
    (209, 2600, 100),
    (210, 4854, 912),
    (211, 4827, 1536),
    (212, 4720, 128),
    (213, 3360, 420),
    (214, 3334, 892),
    (215, 3120, 124),
    (216, 3334, 764),
    (217, 3120, 124),
];
const PRIM_FORMAT_420: [(u8, u16, u16); 44] = [
    (114, 1920, 828),
    (116, 1920, 828),
    (96, 1920, 720),
    (106, 1920, 720),
    (97, 1920, 280),
    (107, 1920, 280),
    (117, 1370, 104),
    (119, 1370, 104),
    (118, 1130, 104),
    (120, 1130, 104),
    (115, 2048, 700),
    (101, 2048, 592),
    (102, 2048, 152),
    (218, 1376, 96),
    (219, 1131, 84),
    (124, 2560, 256),
    (125, 2560, 484),
    (126, 2307, 144),
    (127, 2560, 484),
    (193, 2334, 104),
    (194, 2460, 816),
    (202, 2460, 816),
    (195, 2460, 732),
    (203, 2460, 732),
    (196, 2360, 144),
    (204, 2360, 144),
    (197, 2460, 816),
    (205, 2460, 816),
    (198, 2460, 732),
    (206, 2460, 732),
    (199, 2380, 116),
    (207, 2380, 116),
    (200, 2240, 480),
    (208, 2240, 480),
    (201, 2062, 108),
    (209, 2062, 108),
    (210, 2614, 172),
    (211, 2614, 500),
    (212, 4720, 128),
    (213, 2614, 172),
    (214, 3334, 892),
    (215, 3120, 124),
    (216, 2854, 520),
    (217, 2587, 120),
];

/// dml_max: both operands as floats.
fn dml_max(a: f64, b: f64) -> f64 {
    let (a, b) = (a as f32, b as f32);
    f64::from(if a > b { a } else { b })
}
/// dml_min: both operands as floats.
fn dml_min(a: f64, b: f64) -> f64 {
    let (a, b) = (a as f32, b as f32);
    f64::from(if a < b { a } else { b })
}
/// dml_floor(a, 1): the float truncated.
fn dml_floor(a: f64) -> f64 {
    f64::from((a as f32) as i32 as f32)
}
/// dml_ceil(a, 1): the float plus a double 0.99999, truncated.
fn dml_ceil(a: f64) -> f64 {
    f64::from((f64::from(a as f32) + 0.99999) as i32 as f32)
}

/// dml1_frl_cap_chk_common's intermediates.
struct Common {
    overhead_max: f64,
    f_pixel_clock_max: f64,
    t_line: f64,
    r_frl_char_min: f64,
    c_frl_line: f64,
    audio_packets_line: i32,
    blank_audio_min: i32,
}

/// dml1_frl_cap_chk_common: a compressed stream reserves 192 kHz of audio.
fn common(p: &FrlCapInput) -> Result<Common, FrlCap> {
    let audio_bw_reserve = if p.dsc.is_some() { 192_000.0 } else { 0.0 };
    let lanes = i32::from(p.lanes);
    let f_pixel_clock_nominal = f64::from(p.pixel_clock_100hz) * 100.0;
    let r_bit_nominal = f64::from(p.gbps) * 1.0e9;
    let c_frl_sb = 4 * C_FRL_CB + lanes;
    let sb = f64::from(c_frl_sb);
    let overhead_min = f64::from(lanes) / sb + 8.0 * 4.0 / sb + 2.5 / sb;
    let overhead_max = overhead_min + OVERHEAD_M;
    let f_pixel_clock_max = f_pixel_clock_nominal * (1.0 + TOLERANCE_PIXEL_CLOCK);
    let t_line = f64::from(p.h_active as i32 + p.h_blank as i32) / f_pixel_clock_max;
    let r_bit_min = r_bit_nominal * (1.0 - f64::from(TOLERANCE_FRL_BIT) / 1_000_000.0);
    let r_frl_char_min = r_bit_min / 18.0;
    let c_frl_line = dml_floor(t_line * r_frl_char_min * f64::from(lanes));
    let ap = match p.audio.packet_type {
        0x02 => match p.audio.layout {
            0 => 0.25,
            1 => 1.0,
            _ => 0.0,
        },
        0x08 => 0.25,
        0x09 => 1.0,
        0x07 | 0x0e | 0x0f | 0x0b | 0x0c => return Err(FrlCap::UnsupportedAudio),
        _ => 0.0,
    };
    let r_ap = (dml_max(audio_bw_reserve, f64::from(p.audio.max_rate_hz) * ap)
        + f64::from(2 * ACR_RATE_MAX))
        * (1.0 + TOLERANCE_AUDIO_CLOCK / 1_000_000.0);
    let audio_packets_line = dml_ceil(r_ap * t_line) as i32;
    Ok(Common {
        overhead_max,
        f_pixel_clock_max,
        t_line,
        r_frl_char_min,
        c_frl_line,
        audio_packets_line,
        blank_audio_min: 32 + 32 * audio_packets_line,
    })
}

/// dml1_frl_cap_chk_common, then dml1_frl_cap_chk_uncompressed or, for a
/// DSC stream, dml1_frl_cap_chk_compressed.
pub fn frl_cap_check(p: &FrlCapInput) -> FrlCap {
    let c = match common(p) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match p.dsc {
        Some(dsc) => compressed(p, &c, dsc),
        None => uncompressed(p, &c),
    }
}

fn uncompressed(p: &FrlCapInput, c: &Common) -> FrlCap {
    let lanes = i32::from(p.lanes);
    let h_active = p.h_active as i32;
    let h_blank = p.h_blank as i32;
    let audio_packets_line = c.audio_packets_line;
    let k_420 = if p.encoding == FrlEncoding::Ycbcr420 {
        2
    } else {
        1
    };
    let k_cd = if p.encoding == FrlEncoding::Ycbcr422 {
        1.0
    } else {
        f64::from(p.bpc) / 8.0
    };
    let c_frl_free = dml_max(
        f64::from(h_blank) * k_cd / f64::from(k_420)
            - f64::from(32 * (1 + audio_packets_line))
            - 7.0,
        0.0,
    ) as i32;
    let c_frl_rc_savings =
        dml_floor(dml_max((7.0 / 8.0) * f64::from(c_frl_free) - 4.0, 0.0)) as i32;
    let bpp = (24.0 * k_cd / f64::from(k_420)) as i32;
    let bytes_line = f64::from(bpp * h_active) / 8.0;
    let tb_active = dml_ceil(bytes_line / 3.0) as i32;
    let tb_blank = dml_ceil(f64::from(h_blank) * k_cd / f64::from(k_420)) as i32;
    if c.blank_audio_min > tb_blank {
        return FrlCap::AudioBandwidth;
    }
    let h_total = f64::from(h_active + h_blank);
    let f_tb_average = (c.f_pixel_clock_max / h_total) * f64::from(tb_active + tb_blank);
    let t_active_ref = c.t_line * (f64::from(h_active) / h_total);
    let t_blank_ref = c.t_line * (f64::from(h_blank) / h_total);
    let channel = f64::from(lanes) * c.r_frl_char_min * (1.0 - c.overhead_max);
    let t_active_min = (3.0 / 2.0) * f64::from(tb_active) / channel;
    let t_blank_min = f64::from(tb_blank) / channel;
    let (t_borrowed, borrow) = if t_active_ref >= t_active_min && t_blank_ref >= t_blank_min {
        (0.0, FrlBorrow::None)
    } else if t_active_ref < t_active_min && t_blank_ref >= t_blank_min {
        (t_active_min - t_active_ref, FrlBorrow::FromBlank)
    } else {
        return FrlCap::Borrow;
    };
    if dml_ceil(t_borrowed * f_tb_average) > TB_BORROWED_MAX {
        return FrlCap::MaxBorrow;
    }
    let payload = (dml_ceil((3.0 / 2.0) * f64::from(tb_active)) + f64::from(tb_blank)
        - f64::from(c_frl_rc_savings)) as i32;
    let utilization = f64::from(payload) / c.c_frl_line;
    let margin = 1.0 - (utilization + c.overhead_max);
    if margin < 0.0 && -margin > EPSILON {
        return FrlCap::Margin;
    }
    FrlCap::Ok {
        audio_packets_line: audio_packets_line as u32,
        borrow,
        hc_active: 0,
        hc_blank: 0,
    }
}

/// The CTA primary format's fixed (HCactive, HCblank), unless the sink takes
/// every bpp.
fn primary_format(encoding: FrlEncoding, dsc: FrlDsc) -> Option<(i32, i32)> {
    if dsc.all_bpp || dsc.vic == 0 {
        return None;
    }
    let table: &[(u8, u16, u16)] = match encoding {
        FrlEncoding::Rgb444 => &PRIM_FORMAT_444,
        FrlEncoding::Ycbcr422 => &PRIM_FORMAT_422,
        FrlEncoding::Ycbcr420 => &PRIM_FORMAT_420,
    };
    table
        .iter()
        .find(|e| e.0 == dsc.vic)
        .map(|e| (i32::from(e.1), i32::from(e.2)))
}

fn compressed(p: &FrlCapInput, c: &Common, dsc: FrlDsc) -> FrlCap {
    let lanes = f64::from(p.lanes);
    let h_active = p.h_active as i32;
    let h_blank = p.h_blank as i32;
    let bpp_target = f64::from(dsc.bpp_x16) / 16.0;
    let c_frl_available = dml_floor((1.0 - c.overhead_max) * c.c_frl_line) as i32;
    let bytes_target = (f64::from(dsc.slices as i32)
        * dml_ceil(bpp_target * f64::from(dsc.slice_width as i32) / 8.0))
        as i32;
    let mut hc_active_target = dml_ceil(f64::from(bytes_target) / 3.0) as i32;
    let predefined = primary_format(p.encoding, dsc);
    let mut hc_blank_target = 0;
    if let Some((active, blank)) = predefined {
        hc_active_target = active;
        hc_blank_target = blank;
    }
    let est1 =
        dml_ceil(f64::from(hc_active_target) * (f64::from(h_blank) / f64::from(h_active))) as i32;
    let est2 = dml_max(f64::from(est1), f64::from(c.blank_audio_min)) as i32;
    if predefined.is_none() {
        let room = f64::from(c_frl_available) - 3.0 / 2.0 * f64::from(hc_active_target);
        hc_blank_target = (4.0 * dml_floor(dml_min(f64::from(est2), room) / 4.0)) as i32;
    }
    if c.blank_audio_min > hc_blank_target {
        return FrlCap::AudioBandwidth;
    }
    let h_total = f64::from(h_active + h_blank);
    let f_tb_average =
        c.f_pixel_clock_max / h_total * f64::from(hc_active_target + hc_blank_target);
    let t_active_ref = c.t_line * (f64::from(h_active) / h_total);
    let t_blank_ref = c.t_line - t_active_ref;
    let t_active_target = dml_max(
        f64::from(hc_active_target) / f_tb_average,
        (3.0 / 2.0 * f64::from(hc_active_target))
            / (lanes * c.r_frl_char_min * (1.0 - c.overhead_max)),
    );
    let t_blank_target = c.t_line - t_active_target;
    let tb_borrowed = t_active_target * f_tb_average - f64::from(hc_active_target);
    let borrow = if t_blank_target - t_blank_ref > DBL_EPSILON {
        FrlBorrow::FromActive
    } else if t_active_target - t_active_ref > DBL_EPSILON {
        FrlBorrow::FromBlank
    } else {
        FrlBorrow::None
    };
    // A NaN fails, as Linux's !(x <= max) does.
    if !matches!(
        tb_borrowed.partial_cmp(&TB_BORROWED_MAX),
        Some(core::cmp::Ordering::Less | core::cmp::Ordering::Equal)
    ) {
        return FrlCap::MaxBorrow;
    }
    let payload =
        (dml_ceil(3.0 / 2.0 * f64::from(hc_active_target)) + f64::from(hc_blank_target)) as i32;
    let utilization = f64::from(payload) / c.c_frl_line;
    let margin = 1.0 - (utilization + c.overhead_max);
    if margin < 0.0 && margin.abs() > EPSILON {
        return FrlCap::Margin;
    }
    FrlCap::Ok {
        audio_packets_line: c.audio_packets_line as u32,
        borrow,
        hc_active: hc_active_target as u32,
        hc_blank: hc_blank_target as u32,
    }
}

/// calculate_compressed_active_time.
fn compressed_active_time(
    h_active: u32,
    h_blank: u32,
    hc_active: i32,
    hc_blank: i32,
    lanes: u32,
    pix_clk: f64,
    gbps: u8,
) -> f64 {
    // Linux's switch defaults (as for 10G) to 10 Gbps.
    let r_bit_nominal = match gbps {
        3 => 3.0e9,
        6 => 6.0e9,
        8 => 8.0e9,
        12 => 12.0e9,
        _ => 10.0e9,
    };
    let f_tb_average = pix_clk / f64::from(h_active + h_blank) * f64::from(hc_active + hc_blank);
    let sb = f64::from((4 * 510 + lanes) as i32);
    let overhead_min = f64::from(lanes) / sb + 8.0 * 4.0 / sb + 2.5 / sb;
    let overhead_max = overhead_min + 0.003;
    let r_bit_min = r_bit_nominal * (1.0 - 300.0 / 1_000_000.0);
    let r_frl_char_min = r_bit_min / 18.0;
    let est1 = f64::from(hc_active) / f_tb_average;
    let est2 = (3.0 / 2.0 * f64::from(hc_active))
        / (f64::from(lanes) * r_frl_char_min * (1.0 - overhead_max));
    if est1 > est2 {
        est1
    } else {
        est2
    }
}

/// frl_modify_borrow_mode_for_dsc_padding without DSC padding (DC's
/// enable_hblank_borrow is off): the borrow mode
/// update_borrow_mode_from_dsc_padding gives the decided link of `lanes` x
/// `gbps` from the capacity check's HCactive/HCblank targets. Linux passes
/// the pixel clock in 100 Hz units here; the arithmetic keeps that, so the
/// tribyte-rate estimate always sets the compressed active time.
pub fn dsc_borrow(
    pixel_clock_100hz: u32,
    h_active: u32,
    h_blank: u32,
    hc_active: u32,
    hc_blank: u32,
    lanes: u8,
    gbps: u8,
) -> FrlBorrow {
    let f_pixel_clock_max = f64::from(pixel_clock_100hz) * (1.0 + 0.005);
    let t_line = f64::from(h_active + h_blank) / f_pixel_clock_max;
    let t_active_target = compressed_active_time(
        h_active,
        h_blank,
        hc_active as i32,
        hc_blank as i32,
        u32::from(lanes),
        f_pixel_clock_max,
        gbps,
    );
    let t_active = t_line * (f64::from(h_active) / f64::from(h_active + h_blank));
    let t_blank = t_line - t_active;
    let t_blank_target = t_line - t_active_target;
    if t_blank_target - t_blank > DBL_EPSILON {
        FrlBorrow::FromActive
    } else if t_active_target - t_active > DBL_EPSILON {
        FrlBorrow::FromBlank
    } else {
        FrlBorrow::None
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const VECTORS: &str = include_str!("../tests/dcn401_frl/vectors.txt");
    const DSC_VECTORS: &str = include_str!("../tests/dcn401_frl/dsc_vectors.txt");

    /// One vector line's numbers: inputs then Linux's outputs.
    fn numbers(line: &str) -> alloc::vec::Vec<i64> {
        let (input, want) = line.split_once(" = ").expect("vector format");
        input
            .split_whitespace()
            .chain(want.split_whitespace())
            .map(|w| w.parse().unwrap())
            .collect()
    }
    fn input(n: &[i64]) -> FrlCapInput {
        FrlCapInput {
            lanes: n[0] as u8,
            gbps: n[1] as u8,
            pixel_clock_100hz: n[2] as u32,
            h_active: n[3] as u32,
            h_blank: n[4] as u32,
            bpc: n[5] as u8,
            encoding: match n[6] {
                0 => FrlEncoding::Rgb444,
                1 => FrlEncoding::Ycbcr422,
                _ => FrlEncoding::Ycbcr420,
            },
            audio: FrlAudio {
                packet_type: n[7] as u8,
                max_rate_hz: n[8] as u32,
                layout: n[9] as u8,
            },
            dsc: None,
        }
    }
    fn lines(v: &str) -> impl Iterator<Item = &str> {
        v.lines().filter(|l| !l.is_empty() && !l.starts_with('#'))
    }

    /// Every reference vector: Linux's result code, and for a pass the
    /// audio packets per line and borrow mode.
    fn frl_cap_check_matches_linux_dml1_vectors() -> TestResult {
        let mut checked = 0;
        for line in lines(VECTORS) {
            let n = numbers(line);
            let got = frl_cap_check(&input(&n));
            let ok = match got {
                FrlCap::Ok {
                    audio_packets_line,
                    borrow,
                    hc_active: 0,
                    hc_blank: 0,
                } => {
                    n[10] == 0
                        && i64::from(audio_packets_line) == n[11]
                        && n[12] == borrow as i64
                        && borrow != FrlBorrow::FromActive
                }
                FrlCap::Ok { .. } => false,
                other => i64::from(other.code()) == n[10],
            };
            if !ok {
                panic!("FRL capacity {line}: got {got:?}");
            }
            checked += 1;
        }
        if checked < 3000 {
            return TestResult::Fail("vectors missing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/frl-cap",
        frl_cap_check_matches_linux_dml1_vectors
    );

    /// Every compressed vector: Linux's result code, and for a pass the
    /// packets per line, borrow mode, HCactive/HCblank targets and the
    /// decided link's padding borrow mode.
    fn frl_compressed_cap_check_matches_linux_dml1_vectors() -> TestResult {
        let mut checked = 0;
        let mut passed = 0;
        for line in lines(DSC_VECTORS) {
            let n = numbers(line);
            let p = FrlCapInput {
                dsc: Some(FrlDsc {
                    slices: n[10] as u32,
                    slice_width: n[11] as u32,
                    bpp_x16: n[12] as u32,
                    vic: n[13] as u8,
                    all_bpp: n[14] != 0,
                }),
                ..input(&n)
            };
            let got = frl_cap_check(&p);
            let ok = match got {
                FrlCap::Ok {
                    audio_packets_line,
                    borrow,
                    hc_active,
                    hc_blank,
                } => {
                    passed += 1;
                    let padded = dsc_borrow(
                        p.pixel_clock_100hz,
                        p.h_active,
                        p.h_blank,
                        hc_active,
                        hc_blank,
                        p.lanes,
                        p.gbps,
                    );
                    n[15] == 0
                        && i64::from(audio_packets_line) == n[16]
                        && n[17] == borrow as i64
                        && i64::from(hc_active) == n[18]
                        && i64::from(hc_blank) == n[19]
                        && n[20] == padded as i64
                }
                other => i64::from(other.code()) == n[15],
            };
            if !ok {
                panic!("compressed FRL capacity {line}: got {got:?}");
            }
            checked += 1;
        }
        if checked < 2900 || passed < 1500 {
            return TestResult::Fail("vectors missing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/frl-cap",
        frl_compressed_cap_check_matches_linux_dml1_vectors
    );
}
