use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn timing_1080p() -> Timing {
    Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_front_porch: 88,
        v_active: 1080,
        v_total: 1125,
        v_front_porch: 4,
    }
}
fn plane_1080p() -> Plane {
    Plane {
        format: Format::Rgb32,
        surface_width: 1920,
        surface_height: 1080,
        viewport_width: 1920,
        viewport_height: 1080,
        pitch: 1920,
        h_taps: 1,
        v_taps: 1,
    }
}
fn config_1080p() -> Config {
    Config {
        timing: timing_1080p(),
        plane: plane_1080p(),
        dentist_vco_khz: DEFAULT_DENTIST_VCO_KHZ,
        cursors: 0,
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
    config.plane.pitch = 9000;
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
    config.plane.pitch = 8192;
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
                pitch: 1920 * 7,
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
    // Deep sleep: the 1.15 DML factor over 64 bytes per cycle at the line
    // consumption rate, above the PixelClock/16 floor of 9281 kHz.
    if requirements.deep_sleep_dcfclk_khz != 10_674 {
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
    config.plane.pitch = 3840;
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

fn memory_ddr5() -> Memory {
    Memory {
        kind: MemoryKind::Ddr5,
        channels: 4,
        channel_width_bytes: 4,
        speed_mts: 5600,
    }
}
fn clocks_1080p() -> ClockState {
    ClockState {
        dcfclk_khz: 600_000,
        fclk_khz: 1_200_000,
        socclk_khz: 600_000,
        dispclk_khz: 151_579,
        dppclk_khz: 150_000,
        deep_sleep_dcfclk_khz: 10_674,
    }
}

fn dml_watermarks_follow_latency_plus_extra_latency() -> TestResult {
    let config = config_1080p();
    let memory = memory_ddr5();
    let clocks = clocks_1080p();
    let wm = match config.watermarks(&memory, &clocks) {
        Ok(wm) => wm,
        Err(_) => return TestResult::Fail("watermarks rejected"),
    };
    // min(64 B * 600 MHz, 1200 MHz * 32 B) * 80% = 30720 B/us, under the
    // 89600 * 65% the DRAM could supply.
    if wm.return_bandwidth_bytes_per_us != Fx::int(30_720) {
        return TestResult::Fail("return bandwidth");
    }
    // (106 + 102) DCFCLK cycles at 600 MHz, plus 4x4096 reordering bytes and
    // one 8 KiB pixel chunk over the return bandwidth: 0.34667 + 0.8 us.
    if wm.extra_latency_us <= Fx::ratio(11_466, 10_000)
        || wm.extra_latency_us > Fx::ratio(11_467, 10_000)
    {
        return TestResult::Fail("extra latency");
    }
    // Every watermark is a latency plus the shared extra latency.
    if wm.urgent_us != wm.urgent_latency_us.plus(wm.extra_latency_us) {
        return TestResult::Fail("urgent watermark");
    }
    if wm.pstate_change_us != wm.pstate_latency_us.plus(wm.urgent_us) {
        return TestResult::Fail("p-state watermark");
    }
    // The stutter pair differ only by their self-refresh times, and the Z8
    // pair keep the SOC bounding box values rather than the memory table's.
    if wm.stutter_enter_plus_exit_us.minus(wm.stutter_exit_us) != Fx::int(2) {
        return TestResult::Fail("stutter enter/exit difference");
    }
    if wm.z8_stutter_exit_us.minus(wm.stutter_exit_us) != Fx::ratio(2555, 10) {
        return TestResult::Fail("Z8 stutter watermark");
    }
    if wm
        .z8_stutter_enter_plus_exit_us
        .minus(wm.z8_stutter_exit_us)
        != Fx::int(125)
    {
        return TestResult::Fail("Z8 enter/exit difference");
    }
    // LPDDR5 self-refresh is far slower, and its p-state latency differs.
    let lpddr = Memory {
        kind: MemoryKind::Lpddr5,
        ..memory_ddr5()
    };
    let slow = config.watermarks(&lpddr, &clocks).unwrap();
    if slow.sr_exit_us != Fx::int(30)
        || slow.sr_enter_plus_exit_us != Fx::int(32)
        || slow.pstate_latency_us >= wm.pstate_latency_us
    {
        return TestResult::Fail("LPDDR5 latencies");
    }
    if slow.stutter_exit_us <= wm.stutter_exit_us {
        return TestResult::Fail("LPDDR5 stutter watermark not larger");
    }
    // A bandwidth-free memory or clock configuration must not produce a
    // watermark at all.
    for bad in [
        Memory {
            channels: 0,
            ..memory_ddr5()
        },
        Memory {
            channel_width_bytes: 3,
            ..memory_ddr5()
        },
        Memory {
            speed_mts: 0,
            ..memory_ddr5()
        },
    ] {
        if config.watermarks(&bad, &clocks).is_ok() {
            return TestResult::Fail("invalid memory configuration accepted");
        }
    }
    if config
        .watermarks(
            &memory,
            &ClockState {
                deep_sleep_dcfclk_khz: 0,
                ..clocks_1080p()
            },
        )
        .is_ok()
    {
        return TestResult::Fail("stopped clock accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml",
    dml_watermarks_follow_latency_plus_extra_latency
);

fn dml_prefetch_schedule_fits_the_minimum_vstartup() -> TestResult {
    let config = config_1080p();
    let geometry = config.geometry().unwrap();
    let clocks = clocks_1080p();
    let wm = config.watermarks(&memory_ddr5(), &clocks).unwrap();
    let prefetch = match config.prefetch(&geometry, &clocks, &wm) {
        Ok(prefetch) => prefetch,
        Err(_) => return TestResult::Fail("1080p prefetch rejected"),
    };
    // 45 lines of vblank, capped by the 668 us nominal, less one line.
    if prefetch.max_v_startup != 44 {
        return TestResult::Fail("max VStartup");
    }
    // DML's minimum VStartup already has room for this mode.
    if prefetch.v_startup != MIN_VSTARTUP {
        return TestResult::Fail("VStartup search");
    }
    // One source line prefilled plus one partial swath, at swath height one.
    if prefetch.prefetch_source_lines != Fx::int(2)
        || prefetch.v_init_pre_fill != Fx::ONE
        || prefetch.max_num_swath != 1
    {
        return TestResult::Fail("prefetch source lines");
    }
    // The optimised schedule is shorter than the equation-driven one here, so
    // DML takes it: a quarter line of VM, a half line of row, 1.75 of swath.
    if prefetch.dst_y_prefetch != Fx::int(3)
        || prefetch.dst_y_per_vm_vblank != Fx::ratio(1, 4)
        || prefetch.dst_y_per_row_vblank != Fx::ratio(1, 2)
        || prefetch.lines_for_prefetch_pixel_data != Fx::ratio(7, 4)
    {
        return TestResult::Fail("prefetch line budget");
    }
    // Two source lines over 1.75 destination lines, inside the max of four.
    if prefetch.v_ratio_prefetch <= Fx::ratio(114, 100)
        || prefetch.v_ratio_prefetch >= Fx::ratio(115, 100)
    {
        return TestResult::Fail("prefetch VRatio");
    }
    // Pipeline delay is well under a line, so no whole line is lost.
    if prefetch.dst_y_after_scaler != 0 || prefetch.dst_x_after_scaler != 205 {
        return TestResult::Fail("after-scaler delay");
    }
    if prefetch.v_update_offset_pix != 550
        || prefetch.v_update_width_pix != 247
        || prefetch.v_ready_offset_pix != 328
    {
        return TestResult::Fail("VUpdate geometry");
    }
    // TWait at prefetch mode 0 is the p-state latency plus urgent latency,
    // which here exceeds the self-refresh enter+exit alternative.
    if prefetch.t_wait_us != wm.pstate_latency_us.plus(wm.urgent_latency_us) {
        return TestResult::Fail("TWait");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml",
    dml_prefetch_schedule_fits_the_minimum_vstartup
);

fn dml_prefetch_refuses_a_vblank_that_cannot_hold_it() -> TestResult {
    let config = config_1080p();
    let geometry = config.geometry().unwrap();
    let clocks = clocks_1080p();
    let wm = config.watermarks(&memory_ddr5(), &clocks).unwrap();
    // A vblank below DML's minimum VStartup cannot be scheduled at all.
    let mut tight = config;
    tight.timing.v_total = tight.timing.v_active + 6;
    tight.timing.v_front_porch = 2;
    if tight.prefetch(&geometry, &clocks, &wm) != Err(Error::ViewportTooLarge) {
        return TestResult::Fail("tiny vblank accepted");
    }
    // A front porch that consumes the whole blank leaves no blank end at all,
    // which is a malformed timing rather than an unschedulable one.
    let mut degenerate = config;
    degenerate.timing.v_total = degenerate.timing.v_active + 4;
    degenerate.timing.v_front_porch = 4;
    if degenerate.prefetch(&geometry, &clocks, &wm) != Err(Error::Invalid) {
        return TestResult::Fail("front porch consuming the blank accepted");
    }
    // Enough vblank to clear the VStartup floor, but a deep-sleep clock far too
    // slow to cover the fixed DCHUB delays pushes TSetup and TCalc past the
    // whole blank, so no VStartup in range leaves room for prefetch.
    let mut slow = config;
    slow.timing.v_total = slow.timing.v_active + 12;
    let slow_clocks = ClockState {
        deep_sleep_dcfclk_khz: 300,
        ..clocks
    };
    let slow_wm = slow.watermarks(&memory_ddr5(), &slow_clocks).unwrap();
    if slow.prefetch(&geometry, &slow_clocks, &slow_wm) != Err(Error::NoTimeForPrefetch) {
        return TestResult::Fail("unschedulable prefetch accepted");
    }
    // A much wider vblank does not raise the ceiling: DML bounds VStartup by
    // the 668 us nominal blank, which is 45 lines here, not by the actual one.
    let mut roomy = config;
    roomy.timing.v_total = roomy.timing.v_active + 200;
    let generous = roomy.prefetch(&geometry, &clocks, &wm).unwrap();
    if generous.max_v_startup != 44 {
        return TestResult::Fail("nominal vblank did not bound VStartup");
    }
    // A shorter line does fit more lines into that same nominal blank.
    let mut dense = config;
    dense.timing.v_total = dense.timing.v_active + 200;
    dense.timing.h_total = 1100;
    dense.timing.h_active = 1000;
    dense.plane.viewport_width = 1000;
    dense.plane.surface_width = 1000;
    let dense_geometry = dense.geometry().unwrap();
    let packed = dense.prefetch(&dense_geometry, &clocks, &wm).unwrap();
    if packed.max_v_startup <= 44 {
        return TestResult::Fail("shorter line did not raise max VStartup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml",
    dml_prefetch_refuses_a_vblank_that_cannot_hold_it
);
