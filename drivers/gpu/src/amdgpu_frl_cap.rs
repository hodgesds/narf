//! Linux's HDMI FRL capacity check for uncompressed video
//! (dml/dml1_frl_cap_chk.c, dml1_frl_cap_chk_uncompressed), as
//! hpo_enc3_validate_hdmi_frl_output feeds it: whether `lanes` FRL lanes at
//! a nominal rate carry a timing with its audio, and the tribyte borrow
//! mode and audio packets per line the HPO FRL stream encoder then needs.
//!
//! The arithmetic is Linux's own, operation for operation: IEEE doubles,
//! with dml_max/dml_floor/dml_ceil rounding through 32-bit floats as
//! dcn_bw_max2/floor2/ceil2 do (the ceiling adding a double 0.99999 to the
//! float quotient). drivers/gpu/tests/dcn401_frl/check.sh verifies the
//! reference vectors against the Linux source compiled on the host.

/// TB_BORROWED_MAX, C_FRL_CB, TOLERANCE_FRL_BIT (ppm), ACR_RATE_MAX.
const TB_BORROWED_MAX: f64 = 400.0;
const C_FRL_CB: i32 = 510;
const TOLERANCE_FRL_BIT: i32 = 300;
const ACR_RATE_MAX: i32 = 1500;
const EPSILON: f64 = 0.01;
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
}

/// FRL_BORROW_MODE_NONE / _FROM_BLANK (FROM_ACTIVE is never chosen for
/// uncompressed video).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrlBorrow {
    None,
    FromBlank,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrlCap {
    Ok {
        audio_packets_line: u32,
        borrow: FrlBorrow,
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

/// dml_max: both operands as floats.
fn dml_max(a: f64, b: f64) -> f64 {
    let (a, b) = (a as f32, b as f32);
    f64::from(if a > b { a } else { b })
}
/// dml_floor(a, 1): the float truncated.
fn dml_floor(a: f64) -> f64 {
    f64::from((a as f32) as i32 as f32)
}
/// dml_ceil(a, 1): the float plus a double 0.99999, truncated.
fn dml_ceil(a: f64) -> f64 {
    f64::from((f64::from(a as f32) + 0.99999) as i32 as f32)
}

/// dml1_frl_cap_chk_common then dml1_frl_cap_chk_uncompressed.
pub fn frl_cap_check(p: &FrlCapInput) -> FrlCap {
    let lanes = i32::from(p.lanes);
    let h_active = p.h_active as i32;
    let h_blank = p.h_blank as i32;
    let f_pixel_clock_nominal = f64::from(p.pixel_clock_100hz) * 100.0;
    let r_bit_nominal = f64::from(p.gbps) * 1.0e9;
    // Common.
    let c_frl_sb = 4 * C_FRL_CB + lanes;
    let sb = f64::from(c_frl_sb);
    let overhead_min = f64::from(lanes) / sb + 8.0 * 4.0 / sb + 2.5 / sb;
    let overhead_max = overhead_min + OVERHEAD_M;
    let f_pixel_clock_max = f_pixel_clock_nominal * (1.0 + TOLERANCE_PIXEL_CLOCK);
    let t_line = f64::from(h_active + h_blank) / f_pixel_clock_max;
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
        0x07 | 0x0e | 0x0f | 0x0b | 0x0c => return FrlCap::UnsupportedAudio,
        _ => 0.0,
    };
    let r_ap = (dml_max(0.0, f64::from(p.audio.max_rate_hz) * ap) + f64::from(2 * ACR_RATE_MAX))
        * (1.0 + TOLERANCE_AUDIO_CLOCK / 1_000_000.0);
    let audio_packets_line = dml_ceil(r_ap * t_line) as i32;
    let blank_audio_min = 32 + 32 * audio_packets_line;
    // Uncompressed.
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
    if blank_audio_min > tb_blank {
        return FrlCap::AudioBandwidth;
    }
    let h_total = f64::from(h_active + h_blank);
    let f_tb_average = (f_pixel_clock_max / h_total) * f64::from(tb_active + tb_blank);
    let t_active_ref = t_line * (f64::from(h_active) / h_total);
    let t_blank_ref = t_line * (f64::from(h_blank) / h_total);
    let channel = f64::from(lanes) * r_frl_char_min * (1.0 - overhead_max);
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
    let utilization = f64::from(payload) / c_frl_line;
    let margin = 1.0 - (utilization + overhead_max);
    if margin < 0.0 && -margin > EPSILON {
        return FrlCap::Margin;
    }
    FrlCap::Ok {
        audio_packets_line: audio_packets_line as u32,
        borrow,
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const VECTORS: &str = include_str!("../tests/dcn401_frl/vectors.txt");

    /// Every reference vector: Linux's result code, and for a pass the
    /// audio packets per line and borrow mode.
    fn frl_cap_check_matches_linux_dml1_vectors() -> TestResult {
        let mut checked = 0;
        for line in VECTORS
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let Some((input, want)) = line.split_once(" = ") else {
                return TestResult::Fail("vector format");
            };
            let n: alloc::vec::Vec<i64> = input
                .split_whitespace()
                .chain(want.split_whitespace())
                .map(|w| w.parse().unwrap())
                .collect();
            let p = FrlCapInput {
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
            };
            let got = frl_cap_check(&p);
            let ok = match got {
                FrlCap::Ok {
                    audio_packets_line,
                    borrow,
                } => {
                    n[10] == 0
                        && i64::from(audio_packets_line) == n[11]
                        && n[12] == if borrow == FrlBorrow::None { 0 } else { 2 }
                }
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
}
