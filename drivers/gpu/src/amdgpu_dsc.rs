//! Linux's Display Stream Compression decision and configuration for DCN401,
//! ported to be bit-exact (verified against Linux built on the host, see
//! `tests/dcn401_dsc/check.sh`):
//!
//! - `DscSinkCaps::parse` is dc_dsc_parse_dsc_dpcd on DPCD 0x060-0x06F and
//!   the branch decoder caps (0x0A0-0x0A2, zero without a dongle);
//! - `HdmiDscCaps::parse` is DRM's drm_parse_dsc_info as amdgpu_dm's
//!   populate_hdmi_info_from_connector stores it (dc_edid_caps' frl_dsc_*),
//!   and `DscSinkCaps::from_hdmi` is dc_dsc_parse_dsc_edid;
//! - `compute_config` is amdgpu_dm's SST policy for a DP sink without a
//!   dongle (apply_dsc_policy_for_stream): dc_dsc_compute_config with
//!   DCN401's encoder (dsc401_get_single_enc_caps; four DSCs, ODM factor 4;
//!   DSCCLK a third of the highest DISPCLK) and Linux's default policy;
//!   `compute_frl_config` is the same for an HDMI FRL sink (is_frl:
//!   hdmi_dsc_get_num_slices, hdmi_dsc_get_bpp with the CTA preset bpps,
//!   compute_bpp_x16_from_frl_params, the FRL bandwidth range and minimum
//!   bpp), and `bandwidth_range` is dc_dsc_compute_bandwidth_range;
//! - `prepare` is dsc_prepare_config: the PPS with its rate-control
//!   parameters (rc_calc_fpu.c in Linux's own float/double arithmetic, then
//!   drm_dsc_compute_rc_parameters) and the OPTC's bytes per pixel;
//! - `pack_pps` is drm_dsc_pps_payload_pack;
//! - `stream_kbps` and `dsc_kbps` are dc_bandwidth_in_kbps_from_timing and
//!   dc_dsc_stream_bandwidth_in_kbps, in Linux's 31.32 fixed point.
//!
//! Native MST owns DP-to-HDMI converter capability and output policy.
//! eDP-specific panel/AUX lifecycle is outside this module.
#[path = "amdgpu_dsc_qp.rs"]
mod qp;

/// Linux's `struct fixed31_32` (dc/basics/fixpt31_32.c), as the DSC code
/// uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Fixed(pub(crate) i64);
impl Fixed {
    pub(crate) fn int(v: i32) -> Self {
        Self(i64::from(v) << 32)
    }
    /// dc_fixpt_from_fraction: 32 fraction bits by long division, the last
    /// rounded half up.
    pub(crate) fn fraction(numerator: i64, denominator: i64) -> Self {
        let negative = (numerator < 0) ^ (denominator < 0);
        let a = numerator.unsigned_abs();
        let b = denominator.unsigned_abs();
        let mut value = a / b;
        let mut remainder = a % b;
        for _ in 0..32 {
            remainder = remainder.wrapping_shl(1);
            value = value.wrapping_shl(1);
            if remainder >= b {
                value |= 1;
                remainder -= b;
            }
        }
        value = value.wrapping_add(u64::from(remainder.wrapping_shl(1) >= b));
        let v = value as i64;
        Self(if negative { v.wrapping_neg() } else { v })
    }
    /// dc_fixpt_mul: integer and fraction halves, the fraction product
    /// rounded half up.
    pub(crate) fn mul(self, other: Self) -> Self {
        let negative = (self.0 < 0) ^ (other.0 < 0);
        let a = self.0.unsigned_abs();
        let b = other.0.unsigned_abs();
        let (ai, af) = (a >> 32, a & 0xffff_ffff);
        let (bi, bf) = (b >> 32, b & 0xffff_ffff);
        let mut v = ai.wrapping_mul(bi).wrapping_shl(32);
        v = v.wrapping_add(ai.wrapping_mul(bf));
        v = v.wrapping_add(bi.wrapping_mul(af));
        let t = af.wrapping_mul(bf);
        v = v.wrapping_add((t >> 32) + u64::from(t >= 1 << 31));
        let v = v as i64;
        Self(if negative { v.wrapping_neg() } else { v })
    }
    pub(crate) fn div(self, other: Self) -> Self {
        Self::fraction(self.0, other.0)
    }
    pub(crate) fn div_int(self, v: i64) -> Self {
        Self::fraction(self.0, Self::int(v as i32).0)
    }
    pub(crate) fn mul_int(self, v: i32) -> Self {
        self.mul(Self::int(v))
    }
    pub(crate) fn add_int(self, v: i32) -> Self {
        Self(self.0.wrapping_add(Self::int(v).0))
    }
    pub(crate) fn sub_int(self, v: i32) -> Self {
        Self(self.0.wrapping_sub(Self::int(v).0))
    }
    pub(crate) fn add(self, other: Self) -> Self {
        Self(self.0.wrapping_add(other.0))
    }
    pub(crate) fn sub(self, other: Self) -> Self {
        Self(self.0.wrapping_sub(other.0))
    }
    pub(crate) fn floor(self) -> i32 {
        let v = (self.0.unsigned_abs() >> 32) as i32;
        if self.0 >= 0 {
            v
        } else {
            -v
        }
    }
    pub(crate) fn ceil(self) -> i32 {
        let v = (self.0.unsigned_abs().wrapping_add((1 << 32) - 1) >> 32) as i32;
        if self.0 >= 0 {
            v
        } else {
            -v
        }
    }
}

/// Pixel encodings DSC can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Rgb,
    Ycbcr444,
    Ycbcr422,
    Ycbcr420,
}

/// The DP channel coding a stream rides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkEncoding {
    Dp8b10b,
    Dp128b132b,
    /// DC_LINK_ENCODING_HDMI_FRL: an HDMI link with a verified FRL rate.
    HdmiFrl,
}

/// The parts of a `dc_crtc_timing` DSC reads (no borders).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DscTiming {
    pub pix_clk_100hz: u32,
    pub h_active: u32,
    pub h_total: u32,
    pub v_active: u32,
    pub v_total: u32,
    /// 8, 10 or 12.
    pub bpc: u8,
    pub encoding: Encoding,
}

/// A slice-count set: bit n set for n slices per line.
type Slices = u32;
const fn slices(counts: &[u32]) -> Slices {
    let mut m = 0;
    let mut i = 0;
    while i < counts.len() {
        m |= 1 << counts[i];
        i += 1;
    }
    m
}

/// dsc_dec_dpcd_caps, as dc_dsc_parse_dsc_dpcd fills it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DscSinkCaps {
    pub version: u8,
    pub rc_buffer_size: u32,
    slices: Slices,
    pub lb_bit_depth: u32,
    pub block_pred: bool,
    /// DP_DSC_MAX_BITS_PER_PIXEL (eDP), 1/16 bpp; zero when unset.
    pub max_bpp_x16: u32,
    /// RGB, YCbCr444, simple 422, native 422, native 420 (bits 0-4).
    pub color_formats: u8,
    /// 8, 10, 12 bpc (bits 1-3).
    pub color_depth: u8,
    pub throughput_0_mps: u32,
    pub throughput_1_mps: u32,
    pub max_slice_width: u32,
    pub bpp_increment_div: u32,
    pub branch_throughput_0_mps: u32,
    pub branch_throughput_1_mps: u32,
    pub branch_max_line_width: u32,
    /// An HDMI FRL sink's caps (dc_dsc_parse_dsc_edid's is_frl): its slice
    /// count and bpp follow the HDMI rules.
    pub is_frl: bool,
    /// HF DSC_All_bpp (is_vic_all_bpp).
    pub all_bpp: bool,
    /// HF DSC_TotalChunkKBytes as Linux stores it: 1024 x (1 + the field).
    pub total_chunk_bytes: u32,
}

/// dsc_throughput_from_dpcd.
fn throughput(code: u8) -> u32 {
    match code {
        0 => 0,
        15 => 170,
        1 => 340,
        // 400, 450, ... 1000 MP/s.
        c => 300 + 50 * u32::from(c),
    }
}

/// The branch decoder's overall throughput code (DP 1.4a SCR).
fn branch_throughput(code: u8) -> u32 {
    match code {
        0 => 0,
        1 => 680,
        c => u32::from(c) * 50 + 600,
    }
}

impl DscSinkCaps {
    /// dc_dsc_parse_dsc_dpcd: `basic` is DPCD 0x060-0x06F, `branch`
    /// 0x0A0-0x0A2 (zero for a sink without a dongle). None without DSC
    /// support or with a field Linux rejects.
    pub fn parse(basic: &[u8; 16], branch: &[u8; 3]) -> Option<Self> {
        if basic[0] & 1 == 0 {
            return None;
        }
        let block = match basic[2] & 3 {
            0 => 1024,
            1 => 4 * 1024,
            2 => 16 * 1024,
            _ => 64 * 1024,
        };
        let lb_bit_depth = match basic[5] {
            d @ 0..=7 => u32::from(d) + 9,
            8 => 8,
            _ => return None,
        };
        let s1 = basic[4];
        let mut slices = 0;
        for (bit, count) in [(0, 1), (1, 2), (3, 4), (4, 6), (5, 8), (6, 10), (7, 12)] {
            if s1 & 1 << bit != 0 {
                slices |= 1 << count;
            }
        }
        for (bit, count) in [(0, 16), (1, 20), (2, 24)] {
            if basic[13] & 1 << bit != 0 {
                slices |= 1 << count;
            }
        }
        let bpp_increment_div = match basic[15] & 7 {
            0 => 16,
            1 => 8,
            2 => 4,
            3 => 2,
            4 => 1,
            _ => return None,
        };
        Some(Self {
            version: basic[1],
            rc_buffer_size: (u32::from(basic[3]) + 1) * block,
            slices,
            lb_bit_depth,
            block_pred: basic[6] & 1 != 0,
            max_bpp_x16: u32::from(basic[7]) | u32::from(basic[8]) << 8,
            color_formats: basic[9],
            color_depth: basic[10],
            throughput_0_mps: throughput(basic[11] & 0xf) + u32::from(basic[2] >> 3) * 2,
            throughput_1_mps: throughput(basic[11] >> 4),
            max_slice_width: u32::from(basic[12]) * 320,
            bpp_increment_div,
            branch_throughput_0_mps: branch_throughput(branch[0]),
            branch_throughput_1_mps: branch_throughput(branch[1]),
            branch_max_line_width: u32::from(branch[2]) * 320,
            is_frl: false,
            all_bpp: false,
            total_chunk_bytes: 0,
        })
    }
    /// dc_dsc_parse_dsc_edid: an HDMI 2.1 sink's DSC 1.2 decoder from its
    /// HF-VSDB/HF-SCDB fields.
    pub fn from_hdmi(e: &HdmiDscCaps) -> Self {
        // frl_dsc_max_slices: the slice counts and per-slice throughputs
        // (modes 0 and 1) each code stands for; 8 and above as 8.
        let (counts, mode_0, mode_1): (&[u32], u32, u32) = match e.max_slices {
            0 => (&[], 0, 0),
            1 => (&[1], 340, 680),
            2 => (&[1, 2], 340, 680),
            3 => (&[1, 2, 4], 340, 680),
            4 => (&[1, 2, 4, 8], 340, 680),
            5 => (&[1, 2, 4, 8], 400, 800),
            6 => (&[1, 2, 4, 8, 12], 400, 800),
            7 => (&[1, 2, 4, 8, 12], 600, 1200),
            _ => (&[1, 2, 4, 8, 12], 900, 1800),
        };
        let mut s = 0;
        for &n in counts {
            s |= 1 << n;
        }
        Self {
            version: 0x21,
            rc_buffer_size: 0,
            slices: s,
            // HDMI 2.1 Table 7-25.
            lb_bit_depth: 13,
            block_pred: true,
            max_bpp_x16: 0,
            // RGB, YCbCr 4:4:4, native 4:2:2, and native 4:2:0 if declared.
            color_formats: 0x0b | u8::from(e.native_420) << 4,
            color_depth: 2 | u8::from(e.bpc10) << 2 | u8::from(e.bpc12) << 3,
            throughput_0_mps: mode_0,
            throughput_1_mps: mode_1,
            max_slice_width: 2560,
            bpp_increment_div: 16,
            branch_throughput_0_mps: 0,
            branch_throughput_1_mps: 0,
            branch_max_line_width: 0,
            is_frl: true,
            all_bpp: e.all_bpp,
            total_chunk_bytes: 1024 * (1 + u32::from(e.total_chunk_kbytes)),
        }
    }
}

/// An HDMI 2.1 sink's DSC fields (HF-VSDB/HF-SCDB bytes 11-13) as
/// drm_parse_dsc_info reads them and amdgpu_dm's
/// populate_hdmi_info_from_connector stores them in dc_edid_caps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HdmiDscCaps {
    /// frl_dsc_10bpc / frl_dsc_12bpc: DSC_10bpc, DSC_12bpc or DSC_16bpc
    /// (DRM's bpc_supported, cumulative).
    pub bpc10: bool,
    pub bpc12: bool,
    pub all_bpp: bool,
    pub native_420: bool,
    /// frl_dsc_max_slices (get_dsc_max_slices: DSC_MaxSlices 1-7, else 0).
    pub max_slices: u8,
    /// frl_dsc_max_frl_rate (get_max_frl_rate: DSC_Max_FRL_Rate 1-6, else 0).
    pub max_frl_rate: u8,
    /// DSC_TotalChunkKBytes (6 bits).
    pub total_chunk_kbytes: u8,
}
impl HdmiDscCaps {
    /// drm_parse_hdmi_forum_scds' DSC part: `flags` is HF-SCDS byte 11
    /// (parsed only when present and nonzero), `rate` byte 12 and `chunk`
    /// byte 13 (each ignored when absent or zero). None without DSC_1p2.
    pub fn parse(flags: u8, rate: Option<u8>, chunk: Option<u8>) -> Option<Self> {
        if flags & 0x80 == 0 {
            return None;
        }
        // DSC_16bpc implies 12 and 10, DSC_12bpc implies 10.
        let bpc = if flags & 4 != 0 {
            16
        } else if flags & 2 != 0 {
            12
        } else if flags & 1 != 0 {
            10
        } else {
            8
        };
        let rate = rate.unwrap_or(0);
        Some(Self {
            bpc10: bpc >= 10,
            bpc12: bpc >= 12,
            all_bpp: flags & 8 != 0,
            native_420: flags & 0x40 != 0,
            max_slices: Some(rate & 0xf)
                .filter(|c| (1..=7).contains(c))
                .unwrap_or(0),
            max_frl_rate: Some(rate >> 4).filter(|c| (1..=6).contains(c)).unwrap_or(0),
            total_chunk_kbytes: chunk.unwrap_or(0) & 0x3f,
        })
    }
}

/// dsc_enc_caps (the fields DP SST uses).
struct EncCaps {
    version: u8,
    slices: Slices,
    lb_bit_depth: u32,
    block_pred: bool,
    color_formats: u8,
    color_depth: u8,
    max_slice_width: u32,
    bpp_increment_div: u32,
    max_dsc_throughput_mps: u32,
}

/// build_dsc_enc_caps for DCN401: dsc401_get_single_enc_caps at DSCCLK a
/// third of the highest DISPCLK, widened by ODM combine of up to four DSCs.
fn enc_caps(max_dispclk_khz: u32) -> EncCaps {
    let single = slices(&[1, 2, 3, 4]);
    let has = |n: u32| single & 1 << n != 0;
    let mut s = single;
    // 2x: 1+1, 2+2, 4+4; 3x: 4+4+4; 4x: 1..4 each.
    for (count, from) in [
        (2, 1),
        (4, 2),
        (8, 4),
        (16, 8),
        (12, 4),
        (4, 1),
        (8, 2),
        (12, 3),
        (16, 4),
    ] {
        if has(from) {
            s |= 1 << count;
        }
    }
    EncCaps {
        version: 0x21,
        slices: s,
        lb_bit_depth: 13,
        block_pred: true,
        color_formats: 0x1f,
        color_depth: 0x0e,
        max_slice_width: 5184,
        bpp_increment_div: 16,
        max_dsc_throughput_mps: max_dispclk_khz / 3 * 3 / 1000 * 4,
    }
}

/// The intersected caps setup_dsc_config works from.
struct Common {
    version: u8,
    slices: Slices,
    lb_bit_depth: u32,
    block_pred: bool,
    color_formats: u8,
    color_depth: u8,
    max_slice_width: u32,
    bpp_increment_div: u32,
    max_bpp_x16: u32,
    is_frl: bool,
    all_bpp: bool,
    total_chunk_bytes: u32,
    /// The lanes and per-lane Mbps of an FRL target bandwidth
    /// (convert_bandwidth_to_frl_params), when it is one.
    frl: Option<(u32, u32)>,
}

/// intersect_dsc_caps.
fn intersect(sink: &DscSinkCaps, enc: &EncCaps, encoding: Encoding) -> Option<Common> {
    let version = sink.version.min(enc.version);
    let slices = sink.slices & enc.slices & slices(&[1, 2, 4, 8, 12, 16]);
    let lb_bit_depth = sink.lb_bit_depth.min(enc.lb_bit_depth);
    let color_formats = sink.color_formats & enc.color_formats;
    let color_depth = sink.color_depth & enc.color_depth;
    let max_slice_width = sink.max_slice_width.min(enc.max_slice_width);
    if version == 0
        || slices == 0
        || lb_bit_depth == 0
        || color_formats == 0
        || color_depth == 0
        || max_slice_width == 0
    {
        return None;
    }
    let _ = enc.max_dsc_throughput_mps; // stored, not consulted, by Linux
    let mut bpp_increment_div = sink.bpp_increment_div.min(enc.bpp_increment_div);
    if matches!(encoding, Encoding::Ycbcr422 | Encoding::Ycbcr420) {
        bpp_increment_div = bpp_increment_div.min(8);
    }
    Some(Common {
        version,
        slices,
        lb_bit_depth,
        block_pred: sink.block_pred && enc.block_pred,
        color_formats,
        color_depth,
        max_slice_width,
        bpp_increment_div,
        max_bpp_x16: sink.max_bpp_x16,
        is_frl: sink.is_frl,
        all_bpp: sink.all_bpp,
        total_chunk_bytes: sink.total_chunk_bytes,
        frl: None,
    })
}

fn available(caps: Slices) -> impl DoubleEndedIterator<Item = u32> + Clone {
    [1, 2, 4, 8, 12, 16]
        .into_iter()
        .filter(move |&n| caps & 1 << n != 0)
}
fn inc_slices(caps: Slices, n: u32) -> u32 {
    available(caps).find(|&a| n < a).unwrap_or(n + 1)
}
fn dec_slices(caps: Slices, n: u32) -> u32 {
    if available(caps).next().is_none() && n > 0 {
        return n + 1;
    }
    available(caps)
        .rev()
        .find(|&a| n > a)
        .unwrap_or(n.saturating_sub(1))
}
fn fit_slices_up(caps: Slices, n: u32) -> u32 {
    if available(caps).next().is_none() {
        return n + 1;
    }
    available(caps).find(|&a| n <= a).unwrap_or(n)
}

fn div10_up(v: u32) -> u32 {
    v.div_ceil(10)
}

/// apply_128b_132b_stream_overhead for an uncompressed stream.
fn overhead_128b_132b(t: &DscTiming, kbps: u32) -> u32 {
    let bpp = Fixed::int(kbps as i32).div_int(i64::from(t.pix_clk_100hz / 10));
    let symbols = Fixed::int(t.h_active as i32).mul(bpp).div_int(128);
    let factor = Fixed::int(symbols.ceil()).div(symbols);
    factor.mul_int(kbps as i32).ceil() as u32
}

/// dc_bandwidth_in_kbps_from_timing for an uncompressed stream.
pub fn stream_kbps(t: &DscTiming, link: LinkEncoding) -> u32 {
    let mut kbps = t.pix_clk_100hz / 10 * u32::from(t.bpc) * 3;
    match t.encoding {
        Encoding::Ycbcr420 => kbps /= 2,
        Encoding::Ycbcr422 => kbps = kbps * 2 / 3,
        _ => {}
    }
    if link == LinkEncoding::Dp128b132b {
        kbps = overhead_128b_132b(t, kbps);
    }
    kbps
}

/// dc_dsc_stream_bandwidth_overhead_in_kbps (DP only).
fn overhead_kbps(t: &DscTiming, slices_h: u32, is_dp: bool) -> u32 {
    if !is_dp {
        return 0;
    }
    let refresh = Fixed::int(t.pix_clk_100hz as i32)
        .div_int(i64::from(t.h_total))
        .div_int(i64::from(t.v_total))
        .mul_int(100);
    Fixed::int(slices_h as i32)
        .mul_int(t.v_total as i32)
        .mul_int(256)
        .div_int(1000)
        .mul(refresh)
        .ceil() as u32
}

/// dc_dsc_stream_bandwidth_in_kbps for a DP sink.
pub fn dsc_kbps(t: &DscTiming, bpp_x16: u32, slices_h: u32) -> u32 {
    dsc_kbps_for(t, bpp_x16, slices_h, true)
}

/// dc_dsc_stream_bandwidth_in_kbps for an HDMI FRL sink (no is_dp slice
/// overhead).
pub fn frl_dsc_kbps(t: &DscTiming, bpp_x16: u32) -> u32 {
    dsc_kbps_for(t, bpp_x16, 0, false)
}

fn dsc_kbps_for(t: &DscTiming, bpp_x16: u32, slices_h: u32, is_dp: bool) -> u32 {
    let overhead = overhead_kbps(t, slices_h, is_dp);
    let bpp = Fixed::fraction(i64::from(bpp_x16), 16);
    Fixed::fraction(i64::from(t.pix_clk_100hz), 10)
        .mul(bpp)
        .add_int(overhead as i32)
        .ceil() as u32
}

/// compute_bpp_x16_from_target_bandwidth.
fn bpp_x16_for(
    bandwidth_kbps: u32,
    t: &DscTiming,
    slices_h: u32,
    increment_div: u32,
    is_dp: bool,
) -> u32 {
    let overhead = overhead_kbps(t, slices_h, is_dp);
    let bpp = Fixed::int(bandwidth_kbps as i32)
        .sub_int(overhead as i32)
        .mul_int(10)
        .div_int(i64::from(t.pix_clk_100hz));
    let bpp = Fixed::int(bpp.mul_int(increment_div as i32).floor())
        .div_int(i64::from(increment_div))
        .mul_int(16);
    bpp.floor() as u32
}

/// dc_dsc_get_policy_for_timing with Linux's defaults: minimum slices,
/// slice height 108, the DP bpp bounds capped at 16 bpp; HDMI FRL takes
/// 4:2:2 natively (7 bpp to twice the depth).
struct Policy {
    min_bpp: u32,
    max_bpp: u32,
    ycbcr422_simple: bool,
}
fn policy(t: &DscTiming, link: LinkEncoding) -> Policy {
    let bpc = u32::from(t.bpc);
    let (min_bpp, max_bpp, simple) = match t.encoding {
        Encoding::Ycbcr420 => (6, bpc * 3 / 2, false),
        Encoding::Ycbcr422 if link == LinkEncoding::HdmiFrl => (7, 2 * bpc, false),
        _ => (8, 3 * bpc, true),
    };
    Policy {
        min_bpp,
        max_bpp: max_bpp.min(16),
        ycbcr422_simple: simple,
    }
}

/// The CTA and HDMI VICs of an HDMI stream (dc_crtc_timing vic and
/// hdmi_vic, from its AVI and vendor InfoFrames).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vic {
    pub cta: u8,
    pub hdmi: u8,
}
impl Vic {
    /// get_vic_preset_bpp's (and the FRL capacity check's) CTA VIC: an
    /// HDMI 1.4b 4K VIC stands for its CTA equivalent.
    pub fn cta_equivalent(self) -> u8 {
        match self.hdmi {
            1 => 95,
            2 => 94,
            3 => 93,
            4 => 98,
            _ => self.cta,
        }
    }
}

/// prim_bpp_444/422/420: the HDMI 2.1 compressed bpp (x16) of CTA formats.
const PRIM_BPP_444: [(u8, u16); 58] = [
    (64, 192),
    (77, 192),
    (63, 192),
    (78, 192),
    (93, 192),
    (103, 192),
    (94, 192),
    (104, 192),
    (95, 192),
    (105, 192),
    (114, 192),
    (116, 192),
    (96, 192),
    (106, 192),
    (97, 192),
    (107, 192),
    (117, 192),
    (119, 192),
    (118, 192),
    (120, 192),
    (98, 192),
    (99, 192),
    (100, 192),
    (115, 192),
    (101, 192),
    (102, 192),
    (218, 192),
    (219, 192),
    (121, 192),
    (122, 192),
    (123, 192),
    (124, 192),
    (125, 192),
    (126, 173),
    (127, 192),
    (193, 175),
    (194, 192),
    (202, 192),
    (195, 192),
    (203, 192),
    (196, 192),
    (204, 192),
    (197, 157),
    (205, 157),
    (198, 157),
    (206, 157),
    (199, 159),
    (207, 159),
    (200, 134),
    (208, 134),
    (201, 130),
    (209, 130),
    (210, 182),
    (211, 181),
    (212, 177),
    (213, 163),
    (214, 162),
    (215, 157),
];
const PRIM_BPP_422: [(u8, u16); 47] = [
    (114, 192),
    (116, 192),
    (96, 192),
    (106, 192),
    (97, 192),
    (107, 192),
    (117, 137),
    (119, 137),
    (118, 113),
    (120, 113),
    (115, 192),
    (101, 192),
    (102, 192),
    (218, 192),
    (219, 192),
    (121, 192),
    (122, 192),
    (123, 192),
    (124, 192),
    (125, 192),
    (126, 173),
    (127, 192),
    (193, 175),
    (194, 123),
    (202, 123),
    (195, 123),
    (203, 123),
    (196, 118),
    (204, 118),
    (197, 123),
    (205, 123),
    (198, 123),
    (206, 123),
    (199, 119),
    (207, 119),
    (200, 134),
    (208, 134),
    (201, 130),
    (209, 130),
    (210, 182),
    (211, 181),
    (212, 177),
    (213, 126),
    (214, 125),
    (215, 117),
    (216, 125),
    (217, 117),
];
const PRIM_BPP_420: [(u8, u16); 44] = [
    (114, 192),
    (116, 192),
    (96, 192),
    (106, 192),
    (97, 192),
    (107, 192),
    (117, 137),
    (119, 137),
    (118, 113),
    (120, 113),
    (115, 192),
    (101, 192),
    (102, 192),
    (218, 129),
    (219, 106),
    (124, 192),
    (125, 192),
    (126, 173),
    (127, 192),
    (193, 175),
    (194, 123),
    (202, 123),
    (195, 123),
    (203, 123),
    (196, 118),
    (204, 118),
    (197, 123),
    (205, 123),
    (198, 123),
    (206, 123),
    (199, 119),
    (207, 119),
    (200, 112),
    (208, 112),
    (201, 103),
    (209, 103),
    (210, 98),
    (211, 98),
    (212, 177),
    (213, 98),
    (214, 125),
    (215, 117),
    (216, 107),
    (217, 97),
];

/// get_vic_preset_bpp.
fn vic_preset_bpp(t: &DscTiming, vic: Vic) -> Option<u32> {
    if vic.cta == 0 && vic.hdmi == 0 {
        return None;
    }
    let id = vic.cta_equivalent();
    let table: &[(u8, u16)] = match t.encoding {
        Encoding::Rgb | Encoding::Ycbcr444 => &PRIM_BPP_444,
        Encoding::Ycbcr422 => &PRIM_BPP_422,
        Encoding::Ycbcr420 => &PRIM_BPP_420,
    };
    table.iter().find(|e| e.0 == id).map(|e| u32::from(e.1))
}

/// hdmi_dsc_get_num_slices: HDMI 2.1's slice count for the pixel rate
/// (doubled for 4:4:4), at most 2720 pixels a slice; 0 past 16 slices.
fn hdmi_num_slices(t: &DscTiming) -> u32 {
    let k = if matches!(t.encoding, Encoding::Rgb | Encoding::Ycbcr444) {
        2
    } else {
        1
    };
    let adj = k * t.pix_clk_100hz / 10000 / 2;
    let ratio = adj * t.h_active / t.h_total;
    let mut min_slices = if adj <= 2720 {
        adj.div_ceil(340)
    } else if adj <= 4800 {
        adj.div_ceil(400)
    } else if ratio <= 4800 {
        ratio.div_ceil(600)
    } else {
        ratio.div_ceil(900)
    };
    loop {
        let target = match min_slices {
            ..=1 => 1,
            2 => 2,
            3..=4 => 4,
            5..=8 => 8,
            9..=12 => 12,
            13..=16 => 16,
            _ => return 0,
        };
        min_slices += 1;
        if t.h_active / target <= 2720 {
            return target;
        }
    }
}

/// hdmi_dsc_get_bpp: the highest bpp (x16) whose compressed line fits the
/// sink's chunk buffer, at most 12 bpp (and the CTA preset) unless it takes
/// every bpp; 0 when none does.
fn hdmi_bpp_x16(t: &DscTiming, common: &Common, vic: Vic) -> u32 {
    let bpc = u32::from(t.bpc);
    let (min_bpp, mut max_bpp) = match t.encoding {
        Encoding::Rgb | Encoding::Ycbcr444 => (8, 3 * bpc),
        Encoding::Ycbcr422 => (7, 2 * bpc),
        Encoding::Ycbcr420 => (6, 3 * bpc / 2),
    };
    if !common.all_bpp {
        max_bpp = max_bpp.min(12);
    }
    let slices = hdmi_num_slices(t);
    if slices == 0 {
        return 0;
    }
    let slice_width = t.h_active / slices;
    let decrement = 16 / common.bpp_increment_div;
    let mut x16 = if common.all_bpp {
        max_bpp * 16 - decrement
    } else {
        max_bpp * 16
    };
    let bytes = |x16: u32| slices * slice_width * x16 / 16 / 8;
    loop {
        if x16 <= min_bpp * 16 {
            return 0;
        }
        if bytes(x16) <= common.total_chunk_bytes {
            break;
        }
        x16 -= decrement;
    }
    if !common.all_bpp {
        if let Some(preset) = vic_preset_bpp(t, vic) {
            if bytes(preset) > common.total_chunk_bytes {
                return 0;
            }
            return preset;
        }
    }
    x16
}

/// convert_bandwidth_to_frl_params: the lanes and per-lane Mbps of an
/// exact FRL link bandwidth.
fn frl_params(kbps: u32) -> Option<(u32, u32)> {
    Some(match kbps {
        9_000_000 => (3, 3000),
        18_000_000 => (3, 6000),
        24_000_000 => (4, 6000),
        32_000_000 => (4, 8000),
        40_000_000 => (4, 10000),
        48_000_000 => (4, 12000),
        _ => return None,
    })
}

/// compute_bpp_x16_from_frl_params: the highest bpp (x16) whose tribyte
/// blanking still carries the audio minimum on the sink's DSC FRL link,
/// in Linux's 31.32 fixed point.
fn frl_link_bpp_x16(t: &DscTiming, slices_h: u32, common: &Common) -> u32 {
    let (lanes, rate) = common.frl.unwrap_or((0, 0));
    let (lanes, rate) = (lanes as i32, rate as i32);
    let h_active = t.h_active as i32;
    let h_blank = (t.h_total - t.h_active) as i32;
    let bpc = u32::from(t.bpc);
    let (min_x16, max_x16) = match t.encoding {
        Encoding::Rgb | Encoding::Ycbcr444 => (8 * 16, 3 * 16 * bpc),
        Encoding::Ycbcr422 => (7 * 16, 2 * 16 * bpc),
        Encoding::Ycbcr420 => (6 * 16, 3 * 16 * bpc / 2),
    };
    let mut max_x16 = max_x16.min(256);
    if !common.all_bpp {
        max_x16 = max_x16.min(192);
    }
    let c_frl_sb = 4 * 510 + lanes;
    let pixel_clock = Fixed::int(t.pix_clk_100hz as i32).div_int(10000);
    let r_bit = Fixed::int(rate);
    let tolerance = Fixed::int(5).div_int(1000);
    let overhead_sb = Fixed::int(lanes).div_int(i64::from(c_frl_sb));
    let overhead_rs = Fixed::int(32).div_int(i64::from(c_frl_sb));
    let overhead_map = Fixed::int(25).div_int(i64::from(c_frl_sb * 10));
    let overhead_min = overhead_sb.add(overhead_rs).add(overhead_map);
    let overhead_max = overhead_min.add(Fixed::int(3).div_int(1000));
    let pixel_clock_max = pixel_clock.mul(tolerance.add_int(1));
    let t_line = Fixed::int(h_active + h_blank).div(pixel_clock_max);
    let r_bit_min = r_bit.mul(Fixed::int(1).sub(Fixed::int(300).div_int(1_000_000)));
    let r_frl_char_min = r_bit_min.div_int(18);
    let c_frl_line_int = t_line.mul(r_frl_char_min).mul_int(lanes).floor();
    let c_frl_av_int = Fixed::int(1)
        .sub(overhead_max)
        .mul_int(c_frl_line_int)
        .floor();
    let r_ap = Fixed::int(192_000)
        .max(Fixed::int(48_000 * 4))
        .add(Fixed::int(2 * 1500));
    let tolerance_audio = Fixed::int(1).add(Fixed::int(1000).div_int(1_000_000));
    let r_ap = r_ap.mul(tolerance_audio);
    let packets = r_ap.mul(t_line).div_int(1_000_000).ceil();
    let hc_blank_audio_min = 32 + 32 * packets;
    let mut slice_width = Fixed::int(h_active).div_int(i64::from(slices_h)).ceil();
    if t.encoding == Encoding::Ycbcr420 && slice_width % 2 != 0 {
        slice_width += 1;
    }
    let mut i = max_x16;
    while i >= min_x16 {
        let bytes_target = slices_h as i32
            * Fixed::int((i * slice_width as u32) as i32)
                .div_int(8 * 16)
                .ceil();
        let hc_active_target = Fixed::int(bytes_target).div_int(3).ceil();
        let est1 = Fixed::int(hc_active_target * h_blank)
            .div_int(i64::from(h_active))
            .ceil();
        let est2 = Fixed::int(est1).max(Fixed::int(hc_blank_audio_min)).floor();
        let bandwidth = Fixed::int(3).div_int(2).mul(Fixed::int(hc_active_target));
        let bandwidth = Fixed::int(c_frl_av_int)
            .sub(bandwidth)
            .min(Fixed::int(est2))
            .div_int(4);
        if bandwidth.floor() * 4 >= hc_blank_audio_min {
            return i;
        }
        i -= 1;
    }
    0
}

/// A DSC configuration (dc_dsc_config).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DscConfig {
    pub slices_h: u32,
    pub slices_v: u32,
    /// Target bits per pixel in 1/16 bpp.
    pub bpp_x16: u32,
    pub block_pred: bool,
    pub linebuf_depth: u32,
    pub version_minor: u32,
    /// 4:2:2 sent as simple 4:2:2.
    pub ycbcr422_simple: bool,
    /// An HDMI FRL stream (is_frl); None for DP.
    pub frl: Option<FrlDscLink>,
    /// The input depth compressed, 8, 10 or 12 bpc: the timing's
    /// display_color_depth the configuration was computed for, which Linux
    /// keeps beside dc_dsc_config in the stream's dc_crtc_timing.
    pub bpc: u8,
}

/// What an HDMI FRL DSC stream adds to dc_dsc_config: is_vic_all_bpp, and
/// the sink's frl_dsc_max_frl_rate, the link (FRL rate code) the FRL
/// capacity check takes a DSC stream at whenever a faster one is chosen
/// (validate_hdmi_frl_output's dsc_max_rate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlDscLink {
    pub all_bpp: bool,
    pub max_rate: u8,
}

/// dc_dsc_compute_config as amdgpu_dm's SST policy calls it for a DP sink:
/// DSC only when the uncompressed stream exceeds `target_kbps` (or
/// `force`), at the highest bpp that fits. `max_dispclk_khz` is the
/// board's highest DISPCLK.
pub fn compute_config(
    sink: &DscSinkCaps,
    max_dispclk_khz: u32,
    target_kbps: u32,
    t: &DscTiming,
    link: LinkEncoding,
    force: bool,
) -> Option<DscConfig> {
    compute_with(
        enc_caps(max_dispclk_khz),
        sink,
        max_dispclk_khz,
        target_kbps,
        t,
        link,
        force,
        Vic::default(),
    )
}

/// frl_link_bandwidth_kbps (and link_bw_kbps_from_raw_frl_link_rate_data)
/// of an FRL rate code: lanes x the raw per-lane rate; 0 for none.
pub fn frl_rate_kbps(code: u8) -> u32 {
    match code {
        1 => 9_000_000,
        2 => 18_000_000,
        3 => 24_000_000,
        4 => 32_000_000,
        5 => 40_000_000,
        6 => 48_000_000,
        _ => 0,
    }
}

/// dc_dsc_compute_config as amdgpu_dm's HDMI FRL policy calls it
/// (apply_dsc_policy_for_stream for SIGNAL_TYPE_HDMI_FRL): for an
/// `is_frl` sink, against the bandwidth of its DSC_Max_FRL_Rate
/// (`max_rate`), on DC_LINK_ENCODING_HDMI_FRL, the stream's VICs choosing
/// the HDMI 2.1 bpp. The caller compresses only when the stream's raw
/// bandwidth exceeds the verified FRL link's.
pub fn compute_frl_config(
    sink: &DscSinkCaps,
    max_dispclk_khz: u32,
    max_rate: u8,
    t: &DscTiming,
    vic: Vic,
) -> Option<DscConfig> {
    // Without a DSC rate (which the policy never compresses for) no bpp is
    // decided, as dc_dsc_compute_config leaves it for a zero target.
    let target = frl_rate_kbps(max_rate);
    if !sink.is_frl {
        return None;
    }
    let cfg = compute_with(
        enc_caps(max_dispclk_khz),
        sink,
        max_dispclk_khz,
        target,
        t,
        LinkEncoding::HdmiFrl,
        false,
        vic,
    )?;
    Some(DscConfig {
        frl: Some(FrlDscLink {
            all_bpp: sink.all_bpp,
            max_rate,
        }),
        ..cfg
    })
}

/// `dsc2_get_enc_caps` (DCN2.0, used by DCN3.0): slices 1-4 on one engine
/// below `DCN20_MAX_PIXEL_CLOCK_Mhz` (1188), two engines (no single slice,
/// eight slices, twice the throughput) from there, four engines (12 and 16
/// slices) past twice it.
fn enc_caps_dcn20(pix_clk_100hz: u32) -> EncCaps {
    const MAX_PIXEL_100HZ: u32 = 1188 * 10_000;
    const MAX_DISPLAY_MHZ: u32 = 1200;
    let mut s = slices(&[1, 2, 3, 4]);
    let mut mps = MAX_DISPLAY_MHZ;
    if pix_clk_100hz >= MAX_PIXEL_100HZ {
        s &= !(1 << 1);
        s |= 1 << 8;
        mps = MAX_DISPLAY_MHZ * 2;
    }
    if pix_clk_100hz > MAX_PIXEL_100HZ * 2 {
        s |= 1 << 12 | 1 << 16;
        mps = MAX_DISPLAY_MHZ * 4;
    }
    EncCaps {
        version: 0x21,
        slices: s,
        lb_bit_depth: 13,
        block_pred: true,
        color_formats: 0x1f,
        color_depth: 0x0e,
        max_slice_width: 5184,
        bpp_increment_div: 16,
        max_dsc_throughput_mps: mps,
    }
}

/// [`compute_config`] with DCN3.0's encoder (`dsc2_get_enc_caps`). DCN3.0's
/// clock manager has no `get_max_clock_khz`, so the minimum ODM slice count
/// is taken from the encoder's total throughput, as
/// `get_min_dsc_slice_count_for_odm` does without one.
pub fn compute_config_dcn20(
    sink: &DscSinkCaps,
    target_kbps: u32,
    t: &DscTiming,
    force: bool,
) -> Option<DscConfig> {
    let enc = enc_caps_dcn20(t.pix_clk_100hz);
    let max_khz = enc.max_dsc_throughput_mps * 1000;
    compute_with(
        enc,
        sink,
        max_khz,
        target_kbps,
        t,
        LinkEncoding::Dp8b10b,
        force,
        Vic::default(),
    )
}

/// setup_dsc_config's slice and caps decisions, before the bpp: the common
/// caps, horizontal slices and slice height.
struct Setup {
    common: Common,
    policy: Policy,
    slices_h: u32,
    slices_v: u32,
    simple: bool,
}

#[allow(clippy::too_many_arguments)]
fn compute_with(
    enc: EncCaps,
    sink: &DscSinkCaps,
    max_dispclk_khz: u32,
    target_kbps: u32,
    t: &DscTiming,
    link: LinkEncoding,
    force: bool,
    vic: Vic,
) -> Option<DscConfig> {
    let s = setup(&enc, sink, max_dispclk_khz, target_kbps, t, link)?;
    let bpp_x16 = if target_kbps > 0 {
        target_bpp_x16(&s, target_kbps, t, link, force, vic)?
    } else {
        0
    };
    Some(DscConfig {
        slices_h: s.slices_h,
        slices_v: s.slices_v,
        bpp_x16,
        block_pred: s.common.block_pred,
        linebuf_depth: s.common.lb_bit_depth,
        version_minor: u32::from(s.common.version & 0xf0) >> 4,
        ycbcr422_simple: s.simple,
        frl: None,
        bpc: t.bpc,
    })
}

fn setup(
    enc: &EncCaps,
    sink: &DscSinkCaps,
    max_dispclk_khz: u32,
    target_kbps: u32,
    t: &DscTiming,
    link: LinkEncoding,
) -> Option<Setup> {
    // get_min_dsc_slice_count_for_odm.
    let pic_width = t.h_active;
    let pic_height = t.v_active;
    let min_odm = if max_dispclk_khz == 0 || enc.max_slice_width == 0 {
        1
    } else {
        Fixed::int(div10_up(t.pix_clk_100hz) as i32)
            .div_int(i64::from(max_dispclk_khz))
            .max(Fixed::int(pic_width as i32).div_int(i64::from(enc.max_slice_width)))
            .ceil() as u32
    };
    let policy = policy(t, link);
    if sink.branch_max_line_width != 0 && sink.branch_max_line_width < pic_width {
        return None;
    }
    let mut common = intersect(sink, enc, t.encoding)?;
    common.frl = frl_params(target_kbps);
    let (format, per_slice_mps, branch_mps, simple) = match t.encoding {
        Encoding::Rgb => (
            1,
            sink.throughput_0_mps,
            sink.branch_throughput_0_mps,
            false,
        ),
        Encoding::Ycbcr444 => (
            2,
            sink.throughput_0_mps,
            sink.branch_throughput_0_mps,
            false,
        ),
        // Linux's policy sends 4:2:2 as simple 4:2:2, except on HDMI FRL.
        Encoding::Ycbcr422 if policy.ycbcr422_simple => (4, sink.throughput_0_mps, 0, true),
        Encoding::Ycbcr422 => (
            8,
            sink.throughput_1_mps,
            sink.branch_throughput_1_mps,
            false,
        ),
        Encoding::Ycbcr420 => (
            16,
            sink.throughput_1_mps,
            sink.branch_throughput_1_mps,
            false,
        ),
    };
    if common.color_formats & format == 0
        || (branch_mps != 0 && div10_up(t.pix_clk_100hz) > branch_mps * 1000)
    {
        return None;
    }
    let depth = match t.bpc {
        8 => 2,
        10 => 4,
        12 => 8,
        _ => return None,
    };
    if common.color_depth & depth == 0 {
        return None;
    }
    let caps = common.slices;
    let mut max_slices = available(caps).last().unwrap_or(0);
    while max_slices > 0 && pic_width % max_slices != 0 {
        max_slices = dec_slices(caps, max_slices);
    }
    let mut min_slices = Fixed::int(pic_width as i32)
        .div_int(i64::from(common.max_slice_width))
        .max(Fixed::int(min_odm as i32))
        .ceil() as u32;
    min_slices = fit_slices_up(caps, min_slices);
    while min_slices <= max_slices {
        let per_slice_khz = div10_up(t.pix_clk_100hz) / min_slices;
        if per_slice_khz <= per_slice_mps * 1000 {
            break;
        }
        min_slices = inc_slices(caps, min_slices);
    }
    while pic_width % min_slices != 0 && min_slices <= max_slices {
        min_slices = inc_slices(caps, min_slices);
    }
    if min_slices > max_slices || max_slices == 0 || min_slices == 0 {
        return None;
    }
    // An HDMI FRL sink's slice count is HDMI 2.1's for the pixel rate.
    let slices_h = if sink.is_frl {
        hdmi_num_slices(t)
    } else {
        min_slices
    };
    if slices_h == 0 || pic_width / slices_h > common.max_slice_width {
        return None;
    }
    let mut slice_height = 108.min(pic_height);
    let ycbcr420 = t.encoding == Encoding::Ycbcr420;
    while slice_height < pic_height
        && (pic_height % slice_height != 0 || (ycbcr420 && slice_height % 2 != 0))
    {
        slice_height += 1;
    }
    if (ycbcr420 && slice_height % 2 != 0) || slice_height == 0 {
        return None;
    }
    Some(Setup {
        common,
        policy,
        slices_h,
        slices_v: pic_height / slice_height,
        simple,
    })
}

/// dc_dsc_bw_range: a DSC stream's bpp bounds and their bandwidths, and the
/// uncompressed stream's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BwRange {
    pub min_bpp_x16: u32,
    pub max_bpp_x16: u32,
    pub min_kbps: u32,
    pub max_kbps: u32,
    pub stream_kbps: u32,
}

/// decide_dsc_bandwidth_range: the HDMI rules for an FRL sink, the eDP
/// sink's maximum otherwise when declared, else `min_bpp_x16..=max_bpp_x16`.
#[allow(clippy::too_many_arguments)]
fn bandwidth_range_for(
    min_bpp_x16: u32,
    max_bpp_x16: u32,
    slices_h: u32,
    common: &Common,
    t: &DscTiming,
    link: LinkEncoding,
    vic: Vic,
) -> Option<BwRange> {
    let (min, max) = if common.is_frl {
        let preferred = hdmi_bpp_x16(t, common, vic);
        if vic.cta != 0 {
            // CTA timings follow the HDMI specification strictly.
            let min = if common.all_bpp {
                min_bpp_x16
            } else {
                preferred
            };
            (min, preferred)
        } else {
            let calculated = if vic.hdmi == 0 {
                frl_link_bpp_x16(t, slices_h, common)
            } else {
                0
            };
            let preferred = if calculated != 0 {
                calculated.min(preferred)
            } else {
                preferred
            };
            (min_bpp_x16, max_bpp_x16.min(preferred))
        }
    } else if common.max_bpp_x16 != 0 {
        (min_bpp_x16, common.max_bpp_x16.min(max_bpp_x16))
    } else {
        (min_bpp_x16, max_bpp_x16)
    };
    if max < min || min == 0 {
        return None;
    }
    let is_dp = !common.is_frl;
    let range = BwRange {
        min_bpp_x16: min,
        max_bpp_x16: max,
        stream_kbps: stream_kbps(t, link),
        max_kbps: dsc_kbps_for(t, max, slices_h, is_dp),
        min_kbps: dsc_kbps_for(t, min, slices_h, is_dp),
    };
    (range.max_kbps >= range.min_kbps && range.min_kbps > 0).then_some(range)
}

/// dc_dsc_compute_bandwidth_range with DCN401's encoder: the bpp range
/// (`min_bpp_x16..=max_bpp_x16`, narrowed by the sink's rules) a stream
/// can be compressed to with the slices setup_dsc_config picks, and the
/// bandwidths. None when DSC cannot carry the stream.
pub fn bandwidth_range(
    sink: &DscSinkCaps,
    max_dispclk_khz: u32,
    min_bpp_x16: u32,
    max_bpp_x16: u32,
    t: &DscTiming,
    link: LinkEncoding,
) -> Option<BwRange> {
    let enc = enc_caps(max_dispclk_khz);
    let s = setup(&enc, sink, max_dispclk_khz, 0, t, link)?;
    bandwidth_range_for(
        min_bpp_x16,
        max_bpp_x16,
        s.slices_h,
        &s.common,
        t,
        link,
        Vic::default(),
    )
}

/// The DSC policy's bpp bounds for `t` (dc_dsc_get_policy_for_timing),
/// in 1/16 bpp: what amdgpu_dm's MST DSC search takes as its range.
pub fn policy_bpp_x16(t: &DscTiming, link: LinkEncoding) -> (u32, u32) {
    let p = policy(t, link);
    (p.min_bpp * 16, p.max_bpp * 16)
}

/// decide_dsc_bandwidth_range then decide_dsc_target_bpp_x16. An FRL
/// stream short of even its minimum bandwidth takes the minimum bpp, whose
/// tribyte borrowing the FRL capacity check then validates.
fn target_bpp_x16(
    s: &Setup,
    target_kbps: u32,
    t: &DscTiming,
    link: LinkEncoding,
    force: bool,
    vic: Vic,
) -> Option<u32> {
    let range = bandwidth_range_for(
        s.policy.min_bpp * 16,
        s.policy.max_bpp * 16,
        s.slices_h,
        &s.common,
        t,
        link,
        vic,
    )?;
    let mut bpp = if target_kbps >= range.stream_kbps {
        if force {
            range.max_bpp_x16
        } else {
            0
        }
    } else if target_kbps >= range.max_kbps {
        range.max_bpp_x16
    } else if target_kbps >= range.min_kbps {
        bpp_x16_for(
            target_kbps,
            t,
            s.slices_h,
            s.common.bpp_increment_div,
            !s.common.is_frl,
        )
    } else {
        0
    };
    if target_kbps < range.min_kbps && s.common.is_frl {
        bpp = range.min_bpp_x16;
    }
    (bpp != 0).then_some(bpp)
}

/// drm_dsc_config: the PPS and the rate-control model behind it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pps {
    pub line_buf_depth: u8,
    pub bits_per_component: u8,
    pub convert_rgb: bool,
    pub slice_width: u16,
    pub slice_height: u16,
    pub simple_422: bool,
    pub pic_width: u16,
    pub pic_height: u16,
    pub rc_tgt_offset_high: u8,
    pub rc_tgt_offset_low: u8,
    pub bits_per_pixel: u16,
    pub rc_edge_factor: u8,
    pub rc_quant_incr_limit1: u8,
    pub rc_quant_incr_limit0: u8,
    pub initial_xmit_delay: u16,
    pub initial_dec_delay: u16,
    pub block_pred_enable: bool,
    pub first_line_bpg_offset: u8,
    pub initial_offset: u16,
    /// As the registers take them (the model's thresholds / 64).
    pub rc_buf_thresh: [u16; 14],
    /// (min QP, max QP, 6-bit BPG offset).
    pub rc_range_params: [(u8, u8, u8); 15],
    pub rc_model_size: u16,
    pub flatness_min_qp: u8,
    pub flatness_max_qp: u8,
    pub initial_scale_value: u8,
    pub scale_decrement_interval: u16,
    pub scale_increment_interval: u16,
    pub nfl_bpg_offset: u16,
    pub slice_bpg_offset: u16,
    pub final_offset: u16,
    pub vbr_enable: bool,
    pub mux_word_size: u8,
    pub slice_chunk_size: u16,
    pub rc_bits: u16,
    pub dsc_version_minor: u8,
    pub dsc_version_major: u8,
    pub native_422: bool,
    pub native_420: bool,
    pub second_line_bpg_offset: u8,
    pub nsl_bpg_offset: u16,
    pub second_line_offset_adj: u16,
}

/// DSCCIF_CONFIG0.INPUT_PIXEL_FORMAT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    Rgb = 0,
    Ycbcr444 = 1,
    Simple422 = 2,
    Native422 = 3,
    Native420 = 4,
}

/// dsc_reg_values and dsc_optc_config: what DCN401's DSC, OPTC and stream
/// encoder are programmed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DscRegisters {
    pub pps: Pps,
    pub pixel_format: PixelFormat,
    pub slices_h: u32,
    pub slices_v: u32,
    pub alternate_ich_encoding: bool,
    /// ICH_RESET_AT_END_OF_LINE: 0xF with ODM or several slices.
    pub ich_reset_at_eol: u32,
    pub rc_buffer_model_size: u32,
    pub bpp_x32: u32,
    /// Bytes per pixel in U3.28 (dsc_optc_config).
    pub bytes_per_pixel: u32,
    pub slice_width: u32,
    pub is_444: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Rgb,
    Ycbcr444,
    Native422,
    Native420,
}

/// DSC's float rounding (rc_calc_fpu.c dsc_roundf): half away from zero,
/// truncated.
fn roundf(v: f64) -> f64 {
    (if v < 0.0 { v - 0.5 } else { v + 0.5 }) as i32 as f64
}

/// rc_calc_fpu.c median3.
fn median3(a: i32, b: i32, c: i32) -> i32 {
    let (mut a, mut b, mut c) = (a, b, c);
    if a > b {
        core::mem::swap(&mut a, &mut b);
    }
    if b > c {
        core::mem::swap(&mut b, &mut c);
    }
    if a > b {
        core::mem::swap(&mut b, &mut c);
    }
    b
}

/// get_qp_set.
fn qp_set(mode: Mode, bpc: u8, max: bool, bpp: f32) -> Option<[u8; 15]> {
    use qp::*;
    let table: &[(f32, [u8; 15])] = match (mode, bpc, max) {
        (Mode::Rgb | Mode::Ycbcr444, 8, false) => QP_444_8_MIN,
        (Mode::Rgb | Mode::Ycbcr444, 8, true) => QP_444_8_MAX,
        (Mode::Rgb | Mode::Ycbcr444, 10, false) => QP_444_10_MIN,
        (Mode::Rgb | Mode::Ycbcr444, 10, true) => QP_444_10_MAX,
        (Mode::Rgb | Mode::Ycbcr444, 12, false) => QP_444_12_MIN,
        (Mode::Rgb | Mode::Ycbcr444, 12, true) => QP_444_12_MAX,
        (Mode::Native422, 8, false) => QP_422_8_MIN,
        (Mode::Native422, 8, true) => QP_422_8_MAX,
        (Mode::Native422, 10, false) => QP_422_10_MIN,
        (Mode::Native422, 10, true) => QP_422_10_MAX,
        (Mode::Native422, 12, false) => QP_422_12_MIN,
        (Mode::Native422, 12, true) => QP_422_12_MAX,
        (Mode::Native420, 8, false) => QP_420_8_MIN,
        (Mode::Native420, 8, true) => QP_420_8_MAX,
        (Mode::Native420, 10, false) => QP_420_10_MIN,
        (Mode::Native420, 10, true) => QP_420_10_MAX,
        (Mode::Native420, 12, false) => QP_420_12_MIN,
        (Mode::Native420, 12, true) => QP_420_12_MAX,
        _ => return None,
    };
    // Linux leaves the set unwritten (uninitialised) outside the table;
    // the policy's bpp bounds never get there.
    let index = ((bpp - table[0].0) * 2.0) as i32;
    usize::try_from(index)
        .ok()
        .and_then(|i| table.get(i))
        .map(|e| e.1)
}

/// get_ofs_set: the range BPG offsets, interpolated as Linux does in
/// float and double.
fn ofs_set(mode: Mode, bpp: f32) -> [i32; 15] {
    let b = bpp;
    // (bpp - k) in float, scaled in double, rounded.
    let r = |k: f32, scale: f64| roundf(f64::from(b - k) * scale);
    let pick = |v: f64| v as i32;
    if matches!(mode, Mode::Rgb | Mode::Ycbcr444) {
        // ((bpp <= 6) ? a : ((bpp >= 8 && bpp <= 12) ? b : ((bpp >= 15) ? c :
        //   ((bpp > 6 && bpp < 8) ? a + r(6, s1) : b + r(12, s2)))))
        let five = |a: f64, mid: f64, hi: f64, s2: f64| {
            pick(if b <= 6.0 {
                a
            } else if (8.0..=12.0).contains(&b) {
                mid
            } else if b >= 15.0 {
                hi
            } else if b > 6.0 && b < 8.0 {
                a + r(6.0, 1.0) // Linux's (2 / 2.0)
            } else {
                mid + r(12.0, s2)
            })
        };
        let late = |lo: f64, hi: f64, s: f64| {
            pick(if b <= 12.0 {
                lo
            } else if b >= 15.0 {
                hi
            } else {
                lo + r(12.0, s)
            })
        };
        [
            five(0.0, 2.0, 10.0, 8.0 / 3.0),
            five(-2.0, 0.0, 8.0, 8.0 / 3.0),
            five(-2.0, 0.0, 6.0, 6.0 / 3.0),
            five(-4.0, -2.0, 4.0, 6.0 / 3.0),
            five(-6.0, -4.0, 2.0, 6.0 / 3.0),
            late(-6.0, 0.0, 6.0 / 3.0),
            late(-8.0, -2.0, 6.0 / 3.0),
            late(-8.0, -4.0, 4.0 / 3.0),
            late(-8.0, -6.0, 2.0 / 3.0),
            late(-10.0, -8.0, 2.0 / 3.0),
            -10,
            pick(if b <= 6.0 {
                -12.0
            } else if b >= 8.0 {
                -10.0
            } else {
                -12.0 + r(6.0, 1.0)
            }),
            -12,
            -12,
            -12,
        ]
    } else {
        // Native 4:2:2 interpolates over 8-10 bpp, 4:2:0 over 6-8.
        let (lo_k, hi_k) = if mode == Mode::Native422 {
            (8.0, 10.0)
        } else {
            (6.0, 8.0)
        };
        let lin = |lo: f64, hi: f64, s: f64| {
            pick(if b <= lo_k {
                lo
            } else if b >= hi_k {
                hi
            } else {
                lo + r(lo_k, s)
            })
        };
        let eleventh = if mode == Mode::Native422 {
            pick(if b <= 6.0 {
                -12.0
            } else if b >= 7.0 {
                -10.0
            } else {
                -12.0 + r(6.0, 2.0 / 1.0)
            })
        } else {
            pick(if b <= 4.0 {
                -12.0
            } else if b >= 5.0 {
                -10.0
            } else {
                -12.0 + r(4.0, 2.0 / 1.0)
            })
        };
        [
            lin(2.0, 10.0, 8.0 / 2.0),
            lin(0.0, 8.0, 8.0 / 2.0),
            lin(0.0, 6.0, 6.0 / 2.0),
            lin(-2.0, 4.0, 6.0 / 2.0),
            lin(-4.0, 2.0, 6.0 / 2.0),
            lin(-6.0, 0.0, 6.0 / 2.0),
            lin(-8.0, -2.0, 6.0 / 2.0),
            lin(-8.0, -4.0, 4.0 / 2.0),
            lin(-8.0, -6.0, 1.0),
            lin(-10.0, -8.0, 1.0),
            -10,
            eleventh,
            -12,
            -12,
            -12,
        ]
    }
}

/// rc_params (rc_calc_fpu.c).
struct Rc {
    quant_incr_limit: i32,
    initial_fullness_offset: i32,
    initial_xmit_delay: i32,
    first_line_bpg_offset: i32,
    second_line_bpg_offset: i32,
    flatness_min_qp: i32,
    flatness_max_qp: i32,
    qp_min: [u8; 15],
    qp_max: [u8; 15],
    ofs: [i32; 15],
}

/// _do_calc_rc_params.
fn calc_rc(
    mode: Mode,
    bpc: u8,
    drm_bpp: u16,
    slice_width: i32,
    slice_height: i32,
    minor: u8,
) -> Option<Rc> {
    let mut bpp = (f64::from(drm_bpp as f32) / 16.0) as f32;
    if matches!(mode, Mode::Native422 | Mode::Native420) {
        bpp = (f64::from(bpp) / 2.0) as f32;
    }
    let v11_444 = i32::from(minor == 1 && mode == Mode::Ycbcr444);
    let bpci = i32::from(bpc);
    let limit = match bpc {
        8 => 11,
        10 => 15,
        _ => 19,
    } - v11_444;
    let bpp_group = if matches!(mode, Mode::Rgb | Mode::Ycbcr444) {
        bpp
    } else {
        bpp * 2.0
    };
    let first = 12 + (0.09 * f64::from(34.min(slice_height - 8))) as i32;
    let (initial_fullness_offset, first_line, second_line) = match mode {
        Mode::Native420 => (
            (if bpp >= 6.0 {
                2048.0
            } else if bpp <= 4.0 {
                6144.0
            } else if bpp > 4.0 && bpp <= 5.0 {
                6144.0 - roundf(f64::from((bpp - 4.0) * 512.0))
            } else {
                5632.0 - roundf(f64::from((bpp - 5.0) * 3584.0))
            }) as i32,
            median3(0, first, ((3 * bpci * 3) as f32 - 3.0 * bpp_group) as i32),
            median3(0, 12, ((3 * bpci * 3) as f32 - 3.0 * bpp_group) as i32),
        ),
        Mode::Native422 => (
            (if bpp >= 8.0 {
                2048.0
            } else if bpp <= 7.0 {
                5632.0
            } else {
                5632.0 - roundf(f64::from((bpp - 7.0) * 3584.0))
            }) as i32,
            median3(0, first, ((3 * bpci * 4) as f32 - 3.0 * bpp_group) as i32),
            0,
        ),
        Mode::Rgb | Mode::Ycbcr444 => (
            (if bpp >= 12.0 {
                2048.0
            } else if bpp <= 8.0 {
                6144.0
            } else if bpp > 8.0 && bpp <= 10.0 {
                6144.0 - roundf(f64::from((bpp - 8.0) * 256.0))
            } else {
                5632.0 - roundf(f64::from((bpp - 10.0) * 1792.0))
            }) as i32,
            median3(
                0,
                first,
                (((3 * bpci + if mode == Mode::Ycbcr444 { 0 } else { 2 }) * 3) as f32
                    - 3.0 * bpp_group) as i32,
            ),
            0,
        ),
    };
    let factor: f32 = if matches!(mode, Mode::Rgb | Mode::Ycbcr444) {
        1.0
    } else {
        2.0
    };
    let mut xmit = roundf(8192.0 / 2.0 / f64::from(bpp) / f64::from(factor)) as i32;
    let sw = if matches!(mode, Mode::Native422 | Mode::Native420) {
        slice_width / 2
    } else {
        slice_width
    };
    let padding = if sw % 3 != 0 {
        (3 - sw % 3) * (xmit / sw)
    } else {
        0
    };
    if 3.0 * bpp_group >= (((xmit + 2) / 3) * (3 + i32::from(mode == Mode::Native422))) as f32
        && (xmit + padding) % 3 == 1
    {
        xmit += 1;
    }
    let mut qp_min = qp_set(mode, bpc, false, bpp)?;
    let mut qp_max = qp_set(mode, bpc, true, bpp)?;
    if mode == Mode::Ycbcr444 && minor == 1 {
        for q in qp_min.iter_mut().chain(qp_max.iter_mut()) {
            *q = q.saturating_sub(1);
        }
    }
    Some(Rc {
        quant_incr_limit: limit,
        initial_fullness_offset,
        initial_xmit_delay: xmit,
        first_line_bpg_offset: first_line,
        second_line_bpg_offset: second_line,
        flatness_min_qp: match bpc {
            8 => 3,
            10 => 7,
            _ => 11,
        } - v11_444,
        flatness_max_qp: match bpc {
            8 => 12,
            10 => 16,
            _ => 20,
        } - v11_444,
        qp_min,
        qp_max,
        ofs: ofs_set(mode, bpp),
    })
}

/// drm_dsc_compute_rc_parameters. None for -ERANGE.
fn compute_rc_parameters(c: &mut Pps) -> Option<()> {
    let native = c.native_420 || c.native_422;
    let width = u64::from(c.slice_width) / if native { 2 } else { 1 };
    let bpp = u64::from(c.bits_per_pixel);
    let groups_per_line = width.div_ceil(3);
    c.slice_chunk_size = (width * bpp).div_ceil(8 * 16) as u16;
    let mux = u64::from(c.mux_word_size);
    let bpc4 = 4 * u64::from(c.bits_per_component);
    let mut extra_mux_bits = if c.convert_rgb {
        3 * (mux + bpc4 + 4 - 2)
    } else if c.native_422 {
        4 * mux + (bpc4 + 4) + 3 * bpc4 - 2
    } else {
        3 * mux + (bpc4 + 4) + 2 * bpc4 - 2
    };
    let slice_bits = 8 * u64::from(c.slice_chunk_size) * u64::from(c.slice_height);
    while extra_mux_bits > 0 && slice_bits.wrapping_sub(extra_mux_bits) % mux != 0 {
        extra_mux_bits -= 1;
    }
    // groups_per_line < initial_scale_value - 8, an int compared as unsigned
    // long.
    let scale = i64::from(c.initial_scale_value) - 8;
    if (groups_per_line as i64) < scale || scale < 0 {
        c.initial_scale_value = (groups_per_line + 8) as u8;
    }
    c.scale_decrement_interval = if c.initial_scale_value > 8 {
        (groups_per_line / (u64::from(c.initial_scale_value) - 8)) as u16
    } else {
        4095
    };
    let model = u64::from(c.rc_model_size);
    c.final_offset = model
        .wrapping_sub((u64::from(c.initial_xmit_delay) * bpp + 8) / 16)
        .wrapping_add(extra_mux_bits) as u16;
    if c.final_offset >= c.rc_model_size {
        return None;
    }
    let final_scale = (model * 8) / (model - u64::from(c.final_offset));
    c.nfl_bpg_offset = if c.slice_height > 1 {
        (u64::from(c.first_line_bpg_offset) << 11).div_ceil(u64::from(c.slice_height) - 1) as u16
    } else {
        0
    };
    let groups_total = groups_per_line * u64::from(c.slice_height);
    c.slice_bpg_offset = ((model - u64::from(c.initial_offset) + extra_mux_bits) << 11)
        .div_ceil(groups_total) as u16;
    c.scale_increment_interval = if final_scale > 9 {
        ((u64::from(c.final_offset) << 11)
            / ((u64::from(c.nfl_bpg_offset) + u64::from(c.slice_bpg_offset)) * (final_scale - 9)))
            as u16
    } else {
        0
    };
    let rbs_min = model - u64::from(c.initial_offset)
        + (u64::from(c.initial_xmit_delay) * bpp).div_ceil(16)
        + groups_per_line * u64::from(c.first_line_bpg_offset);
    let hrd_delay = (rbs_min * 16).div_ceil(bpp);
    c.rc_bits = (hrd_delay * bpp / 16) as u16;
    c.initial_dec_delay = (hrd_delay - u64::from(c.initial_xmit_delay)) as u16;
    Some(())
}

/// dsc_prepare_config for one DSC on the stream's pipe (no ODM, no
/// padding): the PPS, rate control and OPTC parameters.
pub fn prepare(t: &DscTiming, cfg: &DscConfig) -> Option<DscRegisters> {
    let (pic_width, pic_height) = (t.h_active, t.v_active);
    let minor = cfg.version_minor;
    let lb = cfg.linebuf_depth;
    let lb_ok = match minor {
        1 => (8..=13).contains(&lb),
        2 => (8..=15).contains(&lb) || lb == 0,
        _ => false,
    };
    if cfg.slices_v == 0
        || cfg.slices_h == 0
        || pic_width == 0
        || pic_height == 0
        || !lb_ok
        || !(96..=0x3ff).contains(&cfg.bpp_x16)
        || pic_height % cfg.slices_v != 0
    {
        return None;
    }
    let (pixel_format, mode) = match t.encoding {
        Encoding::Rgb => (PixelFormat::Rgb, Mode::Rgb),
        Encoding::Ycbcr444 => (PixelFormat::Ycbcr444, Mode::Ycbcr444),
        Encoding::Ycbcr422 if cfg.ycbcr422_simple => (PixelFormat::Simple422, Mode::Ycbcr444),
        Encoding::Ycbcr422 => (PixelFormat::Native422, Mode::Native422),
        Encoding::Ycbcr420 => (PixelFormat::Native420, Mode::Native420),
    };
    let native = matches!(
        pixel_format,
        PixelFormat::Native422 | PixelFormat::Native420
    );
    let bpp_x32 = cfg.bpp_x16 << 1;
    // dsc_init_reg_values, then the stream's fields.
    let mut pps = Pps {
        dsc_version_minor: minor as u8,
        dsc_version_major: 1,
        line_buf_depth: lb as u8,
        bits_per_component: t.bpc,
        block_pred_enable: cfg.block_pred,
        initial_xmit_delay: 170,
        initial_offset: 6144,
        flatness_min_qp: 3,
        flatness_max_qp: 12,
        rc_model_size: 8192,
        rc_edge_factor: 6,
        rc_quant_incr_limit0: 11,
        rc_quant_incr_limit1: 11,
        rc_tgt_offset_low: 3,
        rc_tgt_offset_high: 3,
        pic_width: pic_width as u16,
        pic_height: pic_height as u16,
        slice_width: pic_width.div_ceil(cfg.slices_h) as u16,
        slice_height: (pic_height / cfg.slices_v) as u16,
        bits_per_pixel: if native { bpp_x32 } else { cfg.bpp_x16 } as u16,
        convert_rgb: pixel_format == PixelFormat::Rgb,
        native_422: pixel_format == PixelFormat::Native422,
        native_420: pixel_format == PixelFormat::Native420,
        simple_422: pixel_format == PixelFormat::Simple422,
        ..Pps::default()
    };
    // calc_rc_params' colour mode: simple 4:2:2 is coded as 4:4:4.
    let rc_mode = if pps.convert_rgb { Mode::Rgb } else { mode };
    let rc = calc_rc(
        rc_mode,
        t.bpc,
        pps.bits_per_pixel,
        i32::from(pps.slice_width),
        i32::from(pps.slice_height),
        pps.dsc_version_minor,
    )?;
    // dscc_compute_dsc_parameters.
    pps.initial_scale_value = (8 * 8192 / (8192 - rc.initial_fullness_offset)) as u8;
    pps.rc_quant_incr_limit0 = rc.quant_incr_limit as u8;
    pps.rc_quant_incr_limit1 = rc.quant_incr_limit as u8;
    pps.initial_offset = rc.initial_fullness_offset as u16;
    pps.initial_xmit_delay = rc.initial_xmit_delay as u16;
    pps.first_line_bpg_offset = rc.first_line_bpg_offset as u8;
    pps.second_line_bpg_offset = rc.second_line_bpg_offset as u8;
    pps.flatness_min_qp = rc.flatness_min_qp as u8;
    pps.flatness_max_qp = rc.flatness_max_qp as u8;
    for i in 0..15 {
        pps.rc_range_params[i] = (rc.qp_min[i], rc.qp_max[i], (rc.ofs[i] & 0x3f) as u8);
    }
    pps.rc_model_size = 8192;
    pps.rc_edge_factor = 6;
    pps.rc_tgt_offset_high = 3;
    pps.rc_tgt_offset_low = 3;
    const THRESH: [u16; 14] = [
        896, 1792, 2688, 3584, 4480, 5376, 6272, 6720, 7168, 7616, 7744, 7872, 8000, 8064,
    ];
    pps.rc_buf_thresh = THRESH;
    pps.mux_word_size = if t.bpc <= 10 { 48 } else { 64 };
    compute_rc_parameters(&mut pps)?;
    let bytes_per_pixel =
        (u64::from(pps.slice_chunk_size) * 0x1000_0000).div_ceil(u64::from(pps.slice_width)) as u32;
    // dsc_update_from_dsc_parameters: thresholds as the registers take them.
    for th in pps.rc_buf_thresh.iter_mut() {
        *th >>= 6;
    }
    Some(DscRegisters {
        pps,
        pixel_format,
        slices_h: cfg.slices_h,
        slices_v: cfg.slices_v,
        alternate_ich_encoding: minor != 1,
        ich_reset_at_eol: if cfg.slices_h > 1 { 0xf } else { 0 },
        rc_buffer_model_size: u32::from(pps.rc_bits),
        bpp_x32,
        bytes_per_pixel,
        slice_width: u32::from(pps.slice_width),
        is_444: matches!(
            pixel_format,
            PixelFormat::Rgb | PixelFormat::Ycbcr444 | PixelFormat::Simple422
        ),
    })
}

/// drm_dsc_pps_payload_pack: the 128-byte PPS the sink receives.
pub fn pack_pps(c: &Pps) -> [u8; 128] {
    let mut p = [0u8; 128];
    let be = |p: &mut [u8; 128], at: usize, v: u16| p[at..at + 2].copy_from_slice(&v.to_be_bytes());
    p[0] = c.dsc_version_minor | c.dsc_version_major << 4;
    p[3] = c.line_buf_depth | c.bits_per_component << 4;
    p[4] = ((c.bits_per_pixel & 0x300) >> 8) as u8
        | u8::from(c.vbr_enable) << 2
        | u8::from(c.simple_422) << 3
        | u8::from(c.convert_rgb) << 4
        | u8::from(c.block_pred_enable) << 5;
    p[5] = c.bits_per_pixel as u8;
    be(&mut p, 6, c.pic_height);
    be(&mut p, 8, c.pic_width);
    be(&mut p, 10, c.slice_height);
    be(&mut p, 12, c.slice_width);
    be(&mut p, 14, c.slice_chunk_size);
    p[16] = ((c.initial_xmit_delay & 0x300) >> 8) as u8;
    p[17] = c.initial_xmit_delay as u8;
    be(&mut p, 18, c.initial_dec_delay);
    p[21] = c.initial_scale_value;
    be(&mut p, 22, c.scale_increment_interval);
    p[24] = ((c.scale_decrement_interval & 0xf00) >> 8) as u8;
    p[25] = c.scale_decrement_interval as u8;
    p[27] = c.first_line_bpg_offset;
    be(&mut p, 28, c.nfl_bpg_offset);
    be(&mut p, 30, c.slice_bpg_offset);
    be(&mut p, 32, c.initial_offset);
    be(&mut p, 34, c.final_offset);
    p[36] = c.flatness_min_qp;
    p[37] = c.flatness_max_qp;
    be(&mut p, 38, c.rc_model_size);
    // DSC_RC_EDGE_FACTOR_CONST and the target offset constants.
    p[40] = 6;
    p[41] = c.rc_quant_incr_limit0;
    p[42] = c.rc_quant_incr_limit1;
    p[43] = 3 | 3 << 4;
    for (i, &th) in c.rc_buf_thresh.iter().enumerate() {
        p[44 + i] = th as u8;
    }
    for (i, &(min, max, ofs)) in c.rc_range_params.iter().enumerate() {
        be(
            &mut p,
            58 + 2 * i,
            u16::from(min) << 11 | u16::from(max) << 6 | u16::from(ofs),
        );
    }
    p[88] = u8::from(c.native_422) | u8::from(c.native_420) << 1;
    p[89] = c.second_line_bpg_offset;
    be(&mut p, 90, c.nsl_bpg_offset);
    be(&mut p, 92, c.second_line_offset_adj);
    p
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dsc_tests.rs"]
mod tests;
