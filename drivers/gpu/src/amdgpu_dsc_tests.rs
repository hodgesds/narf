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
