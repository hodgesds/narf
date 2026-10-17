use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn soc() -> dml30::Soc {
    dml30::Soc {
        dcfclk_khz: 1_200_000,
        fabric_khz: 1_200_000,
        socclk_khz: 1_000_000,
        dram_speed_mts: 16_000,
        channels: 12,
        channel_width_bytes: 2,
        max_dispclk_khz: 1_330_000,
        max_dppclk_khz: 1_330_000,
        max_phyclk_khz: 810_000,
        dentist_vco_khz: 3_650_000,
        dchub_refclk_khz: 50_000,
    }
}
fn fix(edid: &mut [u8]) {
    for block in edid.chunks_exact_mut(128) {
        let sum = block[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        block[127] = 0u8.wrapping_sub(sum);
    }
}
/// A 4K60 (594 MHz) preferred DTD, then 1080p60 in the CTA block, with an
/// HDMI VSDB declaring `max_tmds_5mhz` (0 omits the field).
fn sink(hdmi: bool, max_tmds_5mhz: u8) -> Sink {
    let mut e = vec![0u8; 256];
    e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    e[18] = 1;
    e[19] = 4;
    // 3840x2160@60, 594 MHz: 4400x2250, sync 176/88, 8/10.
    e[54..72].copy_from_slice(&[
        0x08, 0xe8, 0x00, 0x30, 0xf2, 0x70, 0x5a, 0x80, 0xb0, 0x58, 0x8a, 0x00, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[126] = 1;
    let ext = &mut e[128..];
    ext[0] = 2;
    ext[1] = 3;
    let mut p = 4;
    if hdmi {
        let len = if max_tmds_5mhz != 0 { 7 } else { 5 };
        ext[p] = 3 << 5 | len;
        ext[p + 1..p + 4].copy_from_slice(&[0x03, 0x0c, 0x00]);
        ext[p + 4] = 0x10;
        if max_tmds_5mhz != 0 {
            ext[p + 7] = max_tmds_5mhz;
        }
        p += 1 + len as usize;
    }
    ext[2] = p as u8;
    // 1080p60 DTD.
    ext[p..p + 18].copy_from_slice(&[
        0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0x00, 0, 0, 0, 0, 0, 0x1e,
    ]);
    fix(&mut e);
    Sink {
        edid: e,
        preferred: None,
        hdmi,
        dpcd: None,
    }
}

fn navi22_modeset_selects_first_unscrambled_tmds_mode() -> TestResult {
    // 4K60 needs scrambling; the first mode that fits is 1080p60.
    let Ok((timing, avi, plan)) = select(&sink(true, 0), &soc(), 3_650_000) else {
        return TestResult::Fail("no HDMI mode");
    };
    if timing.h_active != 1920 || timing.pixel_clock_khz != 148_500 {
        return TestResult::Fail("mode choice");
    }
    // AVI InfoFrame v2, VIC 16 (1080p60), RGB, checksum over HB0..2 + PB1..13.
    let Some(avi) = avi else {
        return TestResult::Fail("HDMI sink without AVI");
    };
    let sum = avi[..3]
        .iter()
        .chain(&avi[4..18])
        .fold(0u8, |a, &b| a.wrapping_add(b));
    if avi[..3] != [0x82, 2, 13] || avi[8] != 16 || sum != 0 {
        return TestResult::Fail("AVI InfoFrame");
    }
    if plan.registers.dlg.min_dst_y_next_start != (1125 - 4) * 4 || plan.prefetch.v_startup == 0 {
        return TestResult::Fail("DML30 plan for the chosen mode");
    }
    // A sink without the HDMI VSDB is DVI: no InfoFrame.
    if select(&sink(false, 0), &soc(), 3_650_000).map(|r| r.1.is_none()) != Ok(true) {
        return TestResult::Fail("DVI sink got an InfoFrame");
    }
    // The VSDB ceiling (here 100 MHz) is honoured.
    if select(&sink(true, 20), &soc(), 3_650_000).err() != Some(Error::NoMode) {
        return TestResult::Fail("VSDB TMDS ceiling ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_selects_first_unscrambled_tmds_mode
);

fn navi22_modeset_test_pattern_draws_eight_bars() -> TestResult {
    let mut row = [0u32; 16];
    test_pattern(0, &mut row);
    if row[0] != 0x00ff_ffff || row[1] != 0x00ff_ffff || row[15] != 0 || row[2] != 0x00ff_ff00 {
        return TestResult::Fail("colour bars");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_test_pattern_draws_eight_bars
);
