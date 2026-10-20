use super::*;
use alloc::string::String;
use core::fmt::Write;
use narf_kernel_test::{kernel_test_in, TestResult};

const VECTORS: &str = include_str!("../tests/dcn401_dsc/mst_vectors.txt");

/// One mst_harness.c line through `compute_link`, with dc_dsc_compute_config
/// as the only shape check (the Linux harness has no pipeline limits).
fn run_vector(input: &str) -> Option<String> {
    let w: Vec<&str> = input.split_whitespace().collect();
    let num = |i: usize| w.get(i).and_then(|v| v.parse::<u32>().ok());
    let link = DscLink {
        encoding: if num(0)? == 1 {
            LinkEncoding::Dp128b132b
        } else {
            LinkEncoding::Dp8b10b
        },
        kbps: num(1)?,
        slots: num(2)? as u8,
        max_dispclk_khz: num(3)?,
    };
    let shared = num(4)?;
    let n = num(5)? as usize;
    let mut streams = Vec::new();
    let mut limits = Vec::new();
    for k in 0..n {
        let b = 6 + 7 * k;
        let caps = if *w.get(b)? == "-" {
            None
        } else {
            let mut dpcd = [0u8; 16];
            for (i, x) in dpcd.iter_mut().enumerate() {
                *x = u8::from_str_radix(w[b].get(2 * i..2 * i + 2)?, 16).ok()?;
            }
            DscSinkCaps::parse(&dpcd, &[0; 3])
        };
        streams.push(DscStream {
            sink: Sink {
                branch: 0,
                port: k as u8 + 1,
            },
            timing: Timing {
                pixel_clock_khz: num(b + 1)? / 10,
                h_active: num(b + 2)?,
                h_total: num(b + 3)?,
                h_front_porch: 8,
                h_sync_width: 32,
                v_active: num(b + 4)?,
                v_total: num(b + 5)?,
                v_front_porch: 3,
                v_sync_width: 5,
                h_sync_positive: true,
                v_sync_positive: false,
            },
            dsc: caps,
        });
        limits.push(num(b + 6)?);
    }
    let fits = |alloc: &[(Sink, u16)]| {
        alloc.iter().zip(&limits).all(|(a, &l)| u32::from(a.1) <= l)
            && alloc.iter().map(|a| u32::from(a.1)).sum::<u32>() <= shared
    };
    let mut out = String::new();
    match compute_link(&streams, &link, &fits, &|s| config(s, &link)) {
        None => out.push_str("FAIL"),
        Some(p) => {
            for (i, p) in p.iter().enumerate() {
                if i > 0 {
                    out.push_str(" | ");
                }
                match p.dsc {
                    Some(c) => write!(
                        out,
                        "{} 1 {} {} {}",
                        p.pbn, c.bpp_x16, c.slices_h, c.slices_v
                    )
                    .ok()?,
                    None => write!(out, "{} 0 0 0 0", p.pbn).ok()?,
                }
            }
        }
    }
    Some(out)
}

/// Every reference vector: Linux's compute_mst_dsc_configs_for_link steps
/// (its own increase_dsc_bpp, try_disable_dsc and
/// set_dsc_configs_from_fairness_vars on dc_dsc.c, with DRM's slot and PBN
/// checks modelled) give each stream's PBN, DSC and bpp. Where Linux leaves
/// a stream flagged compressed with bpp 0 (bpp_x16_from_pbn found no
/// configuration for its fair share), the port refuses the configuration.
fn mst_dsc_fairness_matches_linux_vectors() -> TestResult {
    let (mut checked, mut compressed, mut refused) = (0, 0, 0);
    for line in VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("vector format");
        };
        let bpp_zero = want
            .split(" | ")
            .any(|s| s.split(' ').nth(1) == Some("1") && s.split(' ').nth(2) == Some("0"));
        let want = if bpp_zero { "FAIL" } else { want };
        refused += usize::from(bpp_zero);
        match run_vector(input) {
            Some(got) if got == want => checked += 1,
            Some(got) => panic!("MST DSC vector {input}\n want {want}\n  got {got}"),
            None => return TestResult::Fail("vector input"),
        }
        compressed += usize::from(want.contains(" 1 "));
    }
    if checked < 1400 || compressed < 300 || refused > 20 {
        return TestResult::Fail("vector coverage");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dsc", mst_dsc_fairness_matches_linux_vectors);

/// kbps_to_peak_pbn and kbps_from_pbn: 1.006 peak margin, 8b/10b's 3.1% FEC
/// PBN overhead.
fn mst_dsc_pbn_conversions_match_amdgpu_dm() -> TestResult {
    // 4K144 at 8 bpp: 10.03 Gbps -> 1.006 x 1.031 peak.
    let pbn = peak_pbn(10_034_256, LinkEncoding::Dp8b10b);
    let uhbr = peak_pbn(10_034_256, LinkEncoding::Dp128b132b);
    if pbn != ((10_034_256u64 * 1006 * 1031 / 1_000_000 * 64).div_ceil(432_000)) as i32
        || uhbr != ((10_034_256u64 * 1006 / 1000 * 64).div_ceil(432_000)) as i32
        || kbps_from_pbn(2560) != 2560 * 994 * 8 * 54 / 64
    {
        return TestResult::Fail("PBN conversion");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dsc", mst_dsc_pbn_conversions_match_amdgpu_dm);
