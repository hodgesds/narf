use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn timing_1080p() -> Timing {
    Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        v_active: 1080,
        v_total: 1125,
    }
}
fn plane_1080p() -> Plane {
    Plane {
        format: Format::Rgb32,
        surface_width: 1920,
        surface_height: 1080,
        viewport_width: 1920,
        viewport_height: 1080,
        h_taps: 1,
        v_taps: 1,
    }
}
fn config_1080p() -> Config {
    Config {
        timing: timing_1080p(),
        plane: plane_1080p(),
        dentist_vco_khz: DEFAULT_DENTIST_VCO_KHZ,
    }
}

fn dml_fixed_point_rounds_in_the_conservative_direction() -> TestResult {
    if Fx::ratio(1, 3).times(Fx::int(3)) >= Fx::ONE {
        return TestResult::Fail("truncating product exceeded one");
    }
    if Fx::ratio(7, 2).floor() != 3 || Fx::ratio(7, 2).ceil() != 4 {
        return TestResult::Fail("floor/ceil");
    }
    if Fx::int(4).floor() != 4 || Fx::int(4).ceil() != 4 {
        return TestResult::Fail("exact integers must not round away");
    }
    // A zero denominator saturates high, so a bad input cannot produce a
    // small requirement that silently underflows the pipe.
    if Fx::ONE.over(Fx::ZERO) != Fx::MAX {
        return TestResult::Fail("zero denominator");
    }
    // Saturation, never wrapping.
    if Fx::MAX.plus(Fx::ONE) != Fx::MAX || Fx::MAX.times(Fx::int(2)) != Fx::MAX {
        return TestResult::Fail("overflow wrapped");
    }
    if ceil_multiple(1919, 64) != 1920
        || ceil_multiple(1920, 64) != 1920
        || floor_multiple(1919, 64) != 1856
        || ceil_multiple(7, 0) != 7
    {
        return TestResult::Fail("multiple rounding");
    }
    // The DFS can only divide the VCO by whole steps: 14400000/96 and /95.
    let vco = Fx::int(3_600_000);
    if dfs_up(Fx::int(149_243), vco).ceil() != 150_000 {
        return TestResult::Fail("DFS round up");
    }
    if dfs_down(Fx::int(1_200_000), vco).ceil() != 1_200_000 {
        return TestResult::Fail("DFS round down");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml",
    dml_fixed_point_rounds_in_the_conservative_direction
);

fn dml_geometry_matches_linear_rgb_detile_layout() -> TestResult {
    let geometry = match config_1080p().geometry() {
        Ok(geometry) => geometry,
        Err(_) => return TestResult::Fail("1080p rejected"),
    };
    // Linear 32bpp: a 256-byte request is 64 pixels wide and one line tall.
    if geometry.bytes_per_pixel != 4
        || geometry.block_width_256 != 64
        || geometry.block_height_256 != 1
        || geometry.swath_height != 1
    {
        return TestResult::Fail("block or swath height");
    }
    if geometry.swath_width != 1920 || geometry.swath_width_ub != 1920 {
        return TestResult::Fail("swath width");
    }
    if geometry.det_buffer_bytes != 384 * 1024 {
        return TestResult::Fail("DET size");
    }
    if geometry.h_ratio != Fx::ONE || geometry.v_ratio != Fx::ONE {
        return TestResult::Fail("unscaled ratios");
    }
    // A viewport not on a request boundary still fetches whole requests, and
    // the surface bounds that upper bound.
    let mut config = config_1080p();
    config.plane.viewport_width = 1900;
    config.plane.surface_width = 1920;
    let partial = config.geometry().unwrap();
    if partial.swath_width != 1900 || partial.swath_width_ub != 1920 {
        return TestResult::Fail("partial swath upper bound");
    }
    config.plane.surface_width = 1900;
    let clipped = config.geometry().unwrap();
    if clipped.swath_width_ub != 1920 {
        return TestResult::Fail("upper bound clipped to the surface");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml",
    dml_geometry_matches_linear_rgb_detile_layout
);

fn dml_geometry_refuses_shapes_the_buffers_cannot_hold() -> TestResult {
    // 8192 is the linear swath-width ceiling; one swath may use half the DET.
    let mut config = config_1080p();
    config.timing.h_active = 9000;
    config.timing.h_total = 9500;
    config.plane.surface_width = 9000;
    config.plane.viewport_width = 9000;
    if config.geometry() != Err(Error::ViewportTooLarge) {
        return TestResult::Fail("swath wider than the detile buffer accepted");
    }
    // 64bpp at 8192 wide is 64 KiB per line, still inside half the DET; the
    // line-buffer limit is what rejects a tall-tap configuration.
    let mut config = config_1080p();
    config.plane.format = Format::Rgb64;
    config.plane.v_taps = 8;
    config.plane.surface_width = 8192;
    config.plane.viewport_width = 8192;
    config.timing.h_active = 8192;
    config.timing.h_total = 8500;
    if config.geometry() != Err(Error::ViewportTooLarge) {
        return TestResult::Fail("swath beyond the line buffer accepted");
    }
    for invalid in [
        Config {
            timing: Timing {
                pixel_clock_khz: 0,
                ..timing_1080p()
            },
            ..config_1080p()
        },
        Config {
            timing: Timing {
                h_total: 1920,
                ..timing_1080p()
            },
            ..config_1080p()
        },
        Config {
            dentist_vco_khz: 0,
            ..config_1080p()
        },
        Config {
            plane: Plane {
                surface_width: 1000,
                ..plane_1080p()
            },
            ..config_1080p()
        },
    ] {
        if invalid.geometry() != Err(Error::Invalid) {
            return TestResult::Fail("malformed configuration accepted");
        }
    }
    for unsupported in [
        Config {
            plane: Plane {
                v_taps: 9,
                ..plane_1080p()
            },
            ..config_1080p()
        },
        Config {
            plane: Plane {
                viewport_width: 1920 * 7,
                surface_width: 1920 * 7,
                ..plane_1080p()
            },
            ..config_1080p()
        },
    ] {
        if unsupported.geometry() != Err(Error::Unsupported) {
            return TestResult::Fail("unmodelled scaling accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml",
    dml_geometry_refuses_shapes_the_buffers_cannot_hold
);

fn dml_clock_requirements_land_on_dfs_steps() -> TestResult {
    let config = config_1080p();
    let geometry = config.geometry().unwrap();
    let requirements = match config.requirements(&geometry, 1_200_000) {
        Ok(requirements) => requirements,
        Err(_) => return TestResult::Fail("requirements rejected"),
    };
    // 148500 kHz * 1.005 downspread = 149242.5, which the DFS rounds up to
    // 14400000/96 = 150000. An unscaled plane needs no more DPPCLK than that.
    if requirements.dppclk_khz != 150_000 {
        return TestResult::Fail("DPPCLK requirement");
    }
    // DISPCLK additionally carries the 1% ramping margin: 150734.9 rounds up
    // to 14400000/95 = 151578.9, and the requirement must not round down.
    if requirements.dispclk_khz != 151_579 {
        return TestResult::Fail("DISPCLK requirement");
    }
    // Deep sleep: 1.5 * 1920 * 4 / 64 bytes per cycle over a 12.93 ms line
    // delivery, above the PixelClock/16 floor of 9281 kHz.
    if requirements.deep_sleep_dcfclk_khz != 13_922 {
        return TestResult::Fail("deep sleep DCFCLK");
    }
    // 1920 * 4 bytes per line over a 14.815 us line time.
    if requirements.read_bandwidth_bytes_per_us.ceil() != 519
        || requirements.read_bandwidth_bytes_per_us.floor() != 518
    {
        return TestResult::Fail("read bandwidth");
    }
    if requirements.pscl_throughput != Fx::int(2) {
        return TestResult::Fail("bypassed scaler throughput");
    }
    // A DPM ceiling below the ramped requirement drops the margin rather than
    // refusing the mode; below the bare requirement it reports the real need.
    let clamped = config.requirements(&geometry, 150_000).unwrap();
    if clamped.dispclk_khz != 150_000 {
        return TestResult::Fail("ramping margin not dropped at the ceiling");
    }
    let over = config.requirements(&geometry, 100_000).unwrap();
    if over.dispclk_khz != 150_000 {
        return TestResult::Fail("requirement hidden by a low ceiling");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dml", dml_clock_requirements_land_on_dfs_steps);

fn dml_upscaling_raises_dppclk_above_the_pixel_rate() -> TestResult {
    // A 960-wide viewport scaled to 1920 halves HRatio; a downscale doubles it.
    let mut config = config_1080p();
    config.plane.viewport_width = 3840;
    config.plane.surface_width = 3840;
    config.plane.viewport_height = 2160;
    config.plane.surface_height = 2160;
    config.plane.h_taps = 4;
    config.plane.v_taps = 4;
    let geometry = config.geometry().unwrap();
    if geometry.h_ratio != Fx::int(2) || geometry.v_ratio != Fx::int(2) {
        return TestResult::Fail("downscale ratios");
    }
    let requirements = config.requirements(&geometry, 1_200_000).unwrap();
    // HRatio 2 > 1, so throughput is min(4, 2 * 2 / ceil(4/6)=1) = 4, and the
    // pipe needs HRatio*VRatio/throughput = 1 clock per pixel.
    if requirements.pscl_throughput != Fx::int(4) {
        return TestResult::Fail("scaler throughput with downscaling");
    }
    if requirements.dppclk_khz < 150_000 {
        return TestResult::Fail("DPPCLK below the pixel rate");
    }
    // More than six taps forces at least two DPPCLK per pixel.
    let mut wide = config;
    wide.plane.h_taps = 8;
    wide.plane.v_taps = 8;
    let geometry = wide.geometry().unwrap();
    let doubled = wide.requirements(&geometry, 1_200_000).unwrap();
    if doubled.dppclk_khz < 2 * 148_500 {
        return TestResult::Fail("eight-tap scaler did not double DPPCLK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml",
    dml_upscaling_raises_dppclk_above_the_pixel_rate
);
