use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A 1920x1080p60 detailed timing as an EDID would carry it.
fn detailed() -> DetailedTiming {
    DetailedTiming {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_blanking: 280,
        v_active: 1080,
        v_blanking: 45,
        h_sync_offset: 88,
        h_sync_width: 44,
        v_sync_offset: 4,
        v_sync_width: 5,
        h_image_mm: 530,
        v_image_mm: 300,
        interlaced: false,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
fn pool() -> Pool {
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0x1000_0000),
        virt: 0xffff_8000_0000_0000,
        len: 64 * 1024 * 1024,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: bookkeeping-only pool; no mapping access is performed here.
    unsafe { Pool::from_owned_range(map, 0x2_0000_0000) }.unwrap()
}

fn display_edid_timing_becomes_the_shared_description() -> TestResult {
    let timing = match timing_from_edid(&detailed()) {
        Ok(timing) => timing,
        Err(_) => return TestResult::Fail("1080p EDID timing rejected"),
    };
    // Totals are active plus blanking; the porches and sync carry across.
    if timing.h_total != 2200 || timing.v_total != 1125 {
        return TestResult::Fail("totals");
    }
    if timing.h_front_porch != 88 || timing.h_sync_width != 44 {
        return TestResult::Fail("horizontal porch or sync");
    }
    if timing.v_front_porch != 4 || timing.v_sync_width != 5 {
        return TestResult::Fail("vertical porch or sync");
    }
    if timing.pixel_clock_khz != 148_500 {
        return TestResult::Fail("pixel clock");
    }
    if !timing.h_sync_positive || !timing.v_sync_positive {
        return TestResult::Fail("sync polarity");
    }
    // The blank end the timing generator and the stream encoder both use.
    if timing.h_blank_end() != 148 + 44 || timing.v_blank_end() != 41 {
        return TestResult::Fail("blank end");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-display",
    display_edid_timing_becomes_the_shared_description
);

fn display_refuses_modes_this_pipeline_cannot_drive() -> TestResult {
    // Interlaced is a different pipeline, not a mode to approximate.
    if timing_from_edid(&DetailedTiming {
        interlaced: true,
        ..detailed()
    }) != Err(Error::Unsupported)
    {
        return TestResult::Fail("interlaced mode accepted");
    }
    for bad in [
        DetailedTiming {
            h_active: 0,
            ..detailed()
        },
        DetailedTiming {
            v_active: 0,
            ..detailed()
        },
        DetailedTiming {
            pixel_clock_khz: 0,
            ..detailed()
        },
        // Wider than the linear swath ceiling.
        DetailedTiming {
            h_active: 8193,
            ..detailed()
        },
        // No blanking at all.
        DetailedTiming {
            h_blanking: 0,
            ..detailed()
        },
        DetailedTiming {
            v_blanking: 0,
            ..detailed()
        },
    ] {
        if timing_from_edid(&bad) != Err(Error::Unsupported) {
            return TestResult::Fail("undrivable mode accepted");
        }
    }
    // A front porch and sync that do not fit their own blanking is malformed
    // EDID, which is a different complaint from an unsupported mode.
    for malformed in [
        DetailedTiming {
            h_sync_offset: 240,
            h_sync_width: 44,
            ..detailed()
        },
        DetailedTiming {
            v_sync_offset: 40,
            v_sync_width: 6,
            ..detailed()
        },
    ] {
        if timing_from_edid(&malformed) != Err(Error::Invalid) {
            return TestResult::Fail("malformed blanking accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-display",
    display_refuses_modes_this_pipeline_cannot_drive
);

fn display_scanout_pitch_rounds_out_to_a_whole_request() -> TestResult {
    let pool = pool();
    let timing = timing_from_edid(&detailed()).unwrap();
    let scanout = match Scanout::reserve(&pool, &timing, Format::Rgb32) {
        Ok(scanout) => scanout,
        Err(_) => return TestResult::Fail("1080p scanout rejected"),
    };
    // 1920 * 4 is already a whole 256-byte request, so the pitch is unchanged.
    if scanout.pitch() != 1920 {
        return TestResult::Fail("aligned pitch changed");
    }
    if scanout.size() < 1920 * 4 * 1080 {
        return TestResult::Fail("scanout too small for the mode");
    }
    if scanout.gpu_address() < 0x2_0000_0000 {
        return TestResult::Fail("scanout outside the pool");
    }
    // The published framebuffer describes the surface in bytes, not pixels.
    let fb = scanout.generic_fb();
    if fb.width != 1920 || fb.height != 1080 || fb.pitch != 1920 * 4 || fb.bpp != 32 {
        return TestResult::Fail("published framebuffer geometry");
    }
    // A width whose line is not a whole request must round the pitch out, and
    // the surface must grow to match.
    let mut odd = timing;
    odd.h_active = 1000;
    odd.h_total = 1280;
    let narrow = Scanout::reserve(&pool, &odd, Format::Rgb32).unwrap();
    if narrow.pitch() != 1024 {
        return TestResult::Fail("partial line not rounded to a request");
    }
    if narrow.generic_fb().pitch != 1024 * 4 {
        return TestResult::Fail("published pitch not the rounded one");
    }
    // A mode larger than the pool has no scanout.
    let mut huge = timing;
    huge.h_active = 8192;
    huge.v_active = 4096;
    if Scanout::reserve(&pool, &huge, Format::Rgb64).err() != Some(Error::Allocation) {
        return TestResult::Fail("scanout larger than the pool accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-display",
    display_scanout_pitch_rounds_out_to_a_whole_request
);

fn display_publishes_no_scanout_until_a_stream_runs() -> TestResult {
    // Nothing is published by merely reserving a surface: only a completed
    // enable makes a scanout active, so a console cannot adopt a dark pipe.
    let pool = pool();
    let timing = timing_from_edid(&detailed()).unwrap();
    let published = active_scanout().is_some();
    let scanout = Scanout::reserve(&pool, &timing, Format::Rgb32).unwrap();
    if active_scanout().is_some() != published {
        return TestResult::Fail("reserving a surface published it");
    }
    // Dropping the reservation returns it to the pool for the next mode.
    let available = pool.available();
    drop(scanout);
    if pool.available() <= available {
        return TestResult::Fail("dropped scanout not returned to the pool");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-display",
    display_publishes_no_scanout_until_a_stream_runs
);
