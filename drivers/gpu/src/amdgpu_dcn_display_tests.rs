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

fn display_scanout_clear_blacks_the_surface() -> TestResult {
    // A pool over real memory, so the clear writes somewhere observable.
    const SIZE: usize = 8192;
    let mut backing = alloc::vec![0xffu8; SIZE];
    let map = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0x1000_0000),
        virt: backing.as_mut_ptr() as u64,
        len: SIZE as u64,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: the pool's mapping is this buffer, which outlives every use below.
    let pool = unsafe { Pool::from_owned_range(map, 0x2_0000_0000) }.unwrap();
    // A small surface: 64 pixels of 4 bytes is already a whole request.
    let timing = Timing {
        pixel_clock_khz: 25_000,
        h_active: 64,
        h_total: 80,
        h_front_porch: 4,
        h_sync_width: 4,
        v_active: 4,
        v_total: 8,
        v_front_porch: 1,
        v_sync_width: 1,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    let Ok(mut scanout) = Scanout::reserve(&pool, &timing, Format::Rgb32) else {
        return TestResult::Fail("small scanout rejected");
    };
    // The pool allocates whole pages, so the reservation is a page even though
    // the surface itself is 64 * 4 bytes across four lines.
    let bytes = scanout.size() as usize;
    if bytes != 4096 {
        return TestResult::Fail("scanout size");
    }
    narf_scheduler::block_on_spin(scanout.clear());
    // The whole reservation is black, not just the lines the mode uses, and
    // nothing past it was touched.
    if backing[..bytes].iter().any(|byte| *byte != 0) {
        return TestResult::Fail("surface not cleared");
    }
    if backing[bytes..].iter().any(|byte| *byte != 0xff) {
        return TestResult::Fail("clear wrote past the reservation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-display",
    display_scanout_clear_blacks_the_surface
);

/// What the test observer saw: 0 nothing, 1 a scanout, 2 its removal.
static SEEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Width the observer read back out of `active_scanout` while being called,
/// which would deadlock if `publish` still held its locks.
static READBACK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
fn observer(scanout: Option<GenericFb>) {
    use core::sync::atomic::Ordering;
    match scanout {
        Some(_) => {
            SEEN.store(1, Ordering::Release);
            // Reading the published value from inside the notification must not
            // deadlock against the publish that caused it.
            READBACK.store(
                active_scanout().map(|fb| fb.width).unwrap_or(0),
                Ordering::Release,
            );
        }
        None => SEEN.store(2, Ordering::Release),
    }
}

fn display_scanout_observer_sees_both_edges() -> TestResult {
    use core::sync::atomic::Ordering;
    SEEN.store(0, Ordering::Release);
    READBACK.store(0, Ordering::Release);
    // Take over the observer, remembering whoever had it, so the running
    // system's console policy is put back afterwards.
    let previous = swap_scanout_observer_for_test(Some(observer));
    let restore = |result: TestResult| {
        publish_for_test(None);
        swap_scanout_observer_for_test(previous);
        result
    };
    let fb = GenericFb::new(0x1234_0000, 1920, 1080, 1920 * 4, 32);
    publish_for_test(Some(fb));
    if SEEN.load(Ordering::Acquire) != 1 {
        return restore(TestResult::Fail("observer not told about a new scanout"));
    }
    if READBACK.load(Ordering::Acquire) != 1920 {
        return restore(TestResult::Fail(
            "observer could not read the published scanout",
        ));
    }
    if active_scanout().map(|fb| fb.width) != Some(1920) {
        return restore(TestResult::Fail("scanout not published"));
    }
    publish_for_test(None);
    if SEEN.load(Ordering::Acquire) != 2 {
        return restore(TestResult::Fail("observer not told the scanout went away"));
    }
    if active_scanout().is_some() {
        return restore(TestResult::Fail("scanout still published"));
    }
    // Installing an observer while a scanout already runs must not miss the
    // edge that already happened.
    SEEN.store(0, Ordering::Release);
    publish_for_test(Some(fb));
    swap_scanout_observer_for_test(None);
    SEEN.store(0, Ordering::Release);
    register_scanout_observer(observer);
    if SEEN.load(Ordering::Acquire) != 1 {
        return restore(TestResult::Fail("late observer missed a running scanout"));
    }
    restore(TestResult::Pass)
}
kernel_test_in!(
    "drivers/gpu/dcn-display",
    display_scanout_observer_sees_both_edges
);

/// The widest mode this path accepts must be exactly the widest the timing
/// generator will program — not one column more, which is what an independent
/// `8192` here gave.
fn display_mode_bounds_are_the_ones_the_blocks_enforce() -> TestResult {
    // `ODM0_OPTC_WIDTH_CONTROL__OPTC_SEGMENT_WIDTH_MASK` is 0x00001FFF, so one
    // OPP segment carries 8191 active pixels, and this path bypasses ODM.
    if crate::amdgpu_dcn_otg::MAX_SEGMENT_WIDTH != 8191 {
        return TestResult::Fail("OPTC_SEGMENT_WIDTH is thirteen bits");
    }
    if MAX_WIDTH != crate::amdgpu_dcn_otg::MAX_SEGMENT_WIDTH {
        return TestResult::Fail("the mode bound must be the segment the OTG programs");
    }
    // `DSCL0_RECOUT_SIZE__RECOUT_HEIGHT_MASK` and
    // `DPG0_DPG_DIMENSIONS__DPG_ACTIVE_HEIGHT_MASK` are both 0x3FFF.
    if MAX_HEIGHT != 16383 {
        return TestResult::Fail("the plane's height fields are fourteen bits");
    }
    if MAX_HEIGHT != crate::amdgpu_dcn_plane::MAX_DIMENSION {
        return TestResult::Fail("the height bound must be the plane's own field width");
    }
    // One pipe count, shared: res_cap_dcn314 gives num_timing_generator,
    // num_opp and num_video_plane all as 4.
    if crate::amdgpu_dcn::DCN_PIPES != 4 {
        return TestResult::Fail("DCN 3.1.4 has four pixel pipes");
    }

    // A mode exactly at each bound is accepted, and one past it refused — at
    // this stage, rather than several blocks later.
    let at_width = DetailedTiming {
        h_active: 8191,
        h_blanking: 280,
        ..detailed()
    };
    if timing_from_edid(&at_width).is_err() {
        return TestResult::Fail("a mode at the segment width must be accepted");
    }
    let over_width = DetailedTiming {
        h_active: 8192,
        h_blanking: 280,
        ..detailed()
    };
    if timing_from_edid(&over_width).is_ok() {
        return TestResult::Fail("a mode one column past the segment width must be refused");
    }
    let over_height = DetailedTiming {
        v_active: 16384,
        v_blanking: 45,
        ..detailed()
    };
    if timing_from_edid(&over_height).is_ok() {
        return TestResult::Fail("a mode past the plane's height fields must be refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-display",
    display_mode_bounds_are_the_ones_the_blocks_enforce
);
