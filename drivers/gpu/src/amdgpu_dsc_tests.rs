use super::*;
use alloc::string::String;
use core::fmt::Write;
use narf_kernel_test::{kernel_test_in, TestResult};

const VECTORS: &str = include_str!("../tests/dcn401_dsc/vectors.txt");

/// One vector's output as the harness prints it.
fn run_vector(input: &str) -> Option<String> {
    let w: alloc::vec::Vec<&str> = input.split_whitespace().collect();
    let hex = w.first()?;
    let mut dpcd = [0u8; 16];
    for (i, b) in dpcd.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    let n: alloc::vec::Vec<u32> = w[1..]
        .iter()
        .map(|v| v.parse().ok())
        .collect::<Option<_>>()?;
    let t = DscTiming {
        pix_clk_100hz: n[1],
        h_active: n[2],
        h_total: n[3],
        v_active: n[4],
        v_total: n[5],
        bpc: n[6] as u8,
        encoding: [
            Encoding::Rgb,
            Encoding::Ycbcr444,
            Encoding::Ycbcr422,
            Encoding::Ycbcr420,
        ][n[7] as usize & 3],
    };
    let link = if n[9] != 0 {
        LinkEncoding::Dp128b132b
    } else {
        LinkEncoding::Dp8b10b
    };
    let mut out = String::new();
    write!(out, "{}", stream_kbps(&t, link)).ok()?;
    let cfg = DscSinkCaps::parse(&dpcd, &[0; 3])
        .and_then(|caps| compute_config(&caps, n[0], n[8], &t, link, n[10] != 0));
    let Some(cfg) = cfg else {
        out.push_str(" -");
        return Some(out);
    };
    let Some(regs) = prepare(&t, &cfg) else {
        out.push_str(" ! prepare");
        return Some(out);
    };
    write!(
        out,
        " {} {} {} {} {} {} {} {} {} {} {} ",
        cfg.slices_h,
        cfg.slices_v,
        cfg.bpp_x16,
        u8::from(cfg.block_pred),
        cfg.linebuf_depth,
        cfg.version_minor,
        dsc_kbps(&t, cfg.bpp_x16, cfg.slices_h),
        regs.rc_buffer_model_size,
        regs.bytes_per_pixel,
        regs.slice_width,
        u8::from(regs.is_444),
    )
    .ok()?;
    for b in pack_pps(&regs.pps) {
        write!(out, "{b:02x}").ok()?;
    }
    Some(out)
}

/// Every reference vector: Linux's uncompressed bandwidth, its DSC decision,
/// configuration, rate-control model and packed PPS, byte for byte.
fn dsc_matches_linux_vectors() -> TestResult {
    let mut checked = 0;
    for line in VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("vector format");
        };
        match run_vector(input) {
            Some(got) if got == want => checked += 1,
            Some(got) => panic!("DSC vector {input}\n want {want}\n  got {got}"),
            None => return TestResult::Fail("vector input"),
        }
    }
    if checked < 2000 {
        return TestResult::Fail("too few vectors");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dsc", dsc_matches_linux_vectors);

const FRL_VECTORS: &str = include_str!("../tests/dcn401_dsc/frl_vectors.txt");

fn run_frl_vector(input: &str) -> Option<String> {
    let n: alloc::vec::Vec<u32> = input
        .split_whitespace()
        .map(|v| v.parse().ok())
        .collect::<Option<_>>()?;
    let e = HdmiDscCaps {
        bpc10: n[0] != 0,
        bpc12: n[1] != 0,
        all_bpp: n[2] != 0,
        native_420: n[3] != 0,
        max_slices: n[4] as u8,
        max_frl_rate: n[5] as u8,
        total_chunk_kbytes: n[6] as u8,
    };
    let t = DscTiming {
        pix_clk_100hz: n[8],
        h_active: n[9],
        h_total: n[10],
        v_active: n[11],
        v_total: n[12],
        bpc: n[13] as u8,
        encoding: [
            Encoding::Rgb,
            Encoding::Ycbcr444,
            Encoding::Ycbcr422,
            Encoding::Ycbcr420,
        ][n[14] as usize & 3],
    };
    let vic = Vic {
        cta: n[15] as u8,
        hdmi: n[16] as u8,
    };
    let mut out = String::new();
    write!(out, "{}", stream_kbps(&t, LinkEncoding::HdmiFrl)).ok()?;
    let caps = DscSinkCaps::from_hdmi(&e);
    let Some(cfg) = compute_frl_config(&caps, n[7], e.max_frl_rate, &t, vic) else {
        out.push_str(" -");
        return Some(out);
    };
    if cfg.frl
        != Some(FrlDscLink {
            all_bpp: e.all_bpp,
            max_rate: e.max_frl_rate,
        })
    {
        return None;
    }
    let Some(regs) = prepare(&t, &cfg) else {
        out.push_str(" ! prepare");
        return Some(out);
    };
    write!(
        out,
        " {} {} {} {} {} {} {} {} {} {} {} ",
        cfg.slices_h,
        cfg.slices_v,
        cfg.bpp_x16,
        u8::from(cfg.block_pred),
        cfg.linebuf_depth,
        cfg.version_minor,
        frl_dsc_kbps(&t, cfg.bpp_x16),
        regs.rc_buffer_model_size,
        regs.bytes_per_pixel,
        regs.slice_width,
        u8::from(regs.is_444),
    )
    .ok()?;
    for b in pack_pps(&regs.pps) {
        write!(out, "{b:02x}").ok()?;
    }
    Some(out)
}

/// Every HDMI FRL reference vector: dc_dsc_parse_dsc_edid's caps, the FRL
/// policy's DSC decision (HDMI slices, VIC presets, chunk-buffer and FRL
/// link bpp limits), configuration and PPS, byte for byte.
fn dsc_frl_matches_linux_vectors() -> TestResult {
    let mut checked = 0;
    let mut compressed = 0;
    for line in FRL_VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("vector format");
        };
        match run_frl_vector(input) {
            Some(got) if got == want => checked += 1,
            Some(got) => panic!("FRL DSC vector {input}\n want {want}\n  got {got}"),
            None => return TestResult::Fail("vector input"),
        }
        compressed += usize::from(want.len() > 300);
    }
    if checked < 2900 || compressed < 800 {
        return TestResult::Fail("too few vectors");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dsc", dsc_frl_matches_linux_vectors);

/// drm_parse_dsc_info as populate_hdmi_info_from_connector stores it: no
/// DSC without DSC_1p2, cumulative depths, codes outside the tables zero.
fn hdmi_dsc_caps_parse_like_drm() -> TestResult {
    let want = HdmiDscCaps {
        bpc10: true,
        bpc12: true,
        all_bpp: true,
        native_420: true,
        max_slices: 6,
        max_frl_rate: 6,
        total_chunk_kbytes: 0x3f,
    };
    if HdmiDscCaps::parse(0x4f, Some(0x66), Some(0xff)).is_some()
        || HdmiDscCaps::parse(0xce, Some(0x66), Some(0xff)) != Some(want)
        || HdmiDscCaps::parse(0x81, None, None)
            != Some(HdmiDscCaps {
                bpc10: true,
                ..HdmiDscCaps::default()
            })
        || HdmiDscCaps::parse(0x80, Some(0x78), Some(0))
            != Some(HdmiDscCaps {
                max_slices: 0,
                max_frl_rate: 0,
                ..HdmiDscCaps::default()
            })
    {
        return TestResult::Fail("HF-SCDS DSC fields");
    }
    // dc_dsc_parse_dsc_edid: slice code 7 offers up to 12 slices at 600 MP/s.
    let caps = DscSinkCaps::from_hdmi(&HdmiDscCaps {
        max_slices: 7,
        total_chunk_kbytes: 2,
        ..want
    });
    if caps.slices != slices(&[1, 2, 4, 8, 12])
        || caps.throughput_0_mps != 600
        || caps.throughput_1_mps != 1200
        || caps.color_formats != 0x1b
        || caps.color_depth != 0x0e
        || caps.max_slice_width != 2560
        || caps.total_chunk_bytes != 3072
        || !caps.is_frl
    {
        return TestResult::Fail("dc_dsc_parse_dsc_edid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dsc", hdmi_dsc_caps_parse_like_drm);

/// 31.32 fixed point as Linux rounds it: fractions to nearest (half up),
/// products' fraction half up, ceil/floor by magnitude.
fn dsc_fixed_point_rounds_like_linux() -> TestResult {
    let third = Fixed::fraction(1, 3);
    if third.0 != 0x5555_5555
        || Fixed::fraction(2, 3).0 != 0xaaaa_aaab
        || Fixed::fraction(-1, 2).0 != -(1 << 31)
        || Fixed::int(3).mul(third).0 != 0xffff_ffff
        || Fixed::fraction(7, 2).ceil() != 4
        || Fixed::fraction(7, 2).floor() != 3
        || Fixed::fraction(-7, 2).floor() != -3
    {
        return TestResult::Fail("fixed point");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dsc", dsc_fixed_point_rounds_like_linux);
