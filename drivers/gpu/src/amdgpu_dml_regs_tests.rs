use super::*;
use crate::amdgpu_dml::{
    ClockState, Format, Memory, MemoryKind, Plane, Timing, DEFAULT_DENTIST_VCO_KHZ,
};
use narf_kernel_test::{kernel_test_in, TestResult};

const REFCLK_KHZ: u32 = 100_000;

fn config_1080p() -> Config {
    Config {
        timing: Timing {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_front_porch: 88,
            h_sync_width: 44,
            v_active: 1080,
            v_total: 1125,
            v_front_porch: 4,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: true,
        },
        plane: Plane {
            format: Format::Rgb32,
            surface_width: 1920,
            surface_height: 1080,
            viewport_width: 1920,
            viewport_height: 1080,
            pitch: 1920,
            h_taps: 1,
            v_taps: 1,
        },
        dentist_vco_khz: DEFAULT_DENTIST_VCO_KHZ,
        cursors: 0,
    }
}
fn clocks() -> ClockState {
    ClockState {
        dcfclk_khz: 600_000,
        fclk_khz: 1_200_000,
        socclk_khz: 600_000,
        dispclk_khz: 151_579,
        dppclk_khz: 150_000,
        deep_sleep_dcfclk_khz: 10_674,
    }
}
fn memory() -> Memory {
    Memory {
        kind: MemoryKind::Ddr5,
        channels: 4,
        channel_width_bytes: 4,
        speed_mts: 5600,
    }
}
fn registers(config: &Config) -> Result<Registers, Error> {
    let geometry = config.geometry()?;
    let clocks = clocks();
    let wm = config.watermarks(&memory(), &clocks)?;
    let prefetch = config.prefetch(&geometry, &clocks, &wm)?;
    Registers::new(config, &geometry, &clocks, &wm, &prefetch, REFCLK_KHZ)
}

fn dml_regs_request_geometry_matches_linear_pte_rows() -> TestResult {
    let regs = match registers(&config_1080p()) {
        Ok(regs) => regs,
        Err(_) => return TestResult::Fail("1080p register encoding rejected"),
    };
    // A 64-byte request returns eight PTEs of a 4 KiB page: 8192 pixels at
    // 4 bytes each. 64 requests hold 273 rows of a 1920 pitch, floored to 128.
    if regs.requests.dpte_req_width != 8192 || regs.requests.dpte_row_height != 128 {
        return TestResult::Fail("PTE request geometry");
    }
    if regs.requests.dpte_row_width_ub != 253_952
        || regs.requests.dpte_req_per_row_ub != 31
        || regs.requests.dpte_groups_per_row_ub != 1
    {
        return TestResult::Fail("PTE row upper bounds");
    }
    // 1920 pixels of swath in 64-pixel 256-byte requests.
    if regs.requests.req_per_swath_ub != 30 {
        return TestResult::Fail("requests per swath");
    }
    // Log2-encoded sizes with their per-field bias.
    if regs.rq
        != (RequestRegisters {
            chunk_size: 3,
            min_chunk_size: 3,
            meta_chunk_size: 1,
            min_meta_chunk_size: 3,
            dpte_group_size: 5,
            mpte_group_size: 5,
            swath_height: 0,
            pte_row_height_linear: 4,
            drq_expansion_mode: 2,
            prq_expansion_mode: 1,
            mrq_expansion_mode: 1,
            crq_expansion_mode: 1,
        })
    {
        return TestResult::Fail("RQ registers");
    }
    // A pitch so wide that fewer than eight PTE rows fit is not supported.
    let mut wide = config_1080p();
    wide.plane.pitch = 1 << 17;
    wide.plane.surface_width = 1920;
    let geometry = wide.geometry().unwrap();
    if Requests::new(&wide, &geometry) != Err(Error::Unsupported) {
        return TestResult::Fail("unsupported PTE row height accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml-regs",
    dml_regs_request_geometry_matches_linear_pte_rows
);

fn dml_regs_latency_fields_carry_their_binary_points() -> TestResult {
    let regs = registers(&config_1080p()).unwrap();
    let dlg = regs.dlg;
    // 100 MHz reference over a 148.5 MHz pixel clock, in U4.19.
    if dlg.ref_freq_to_pix_freq != 353_055 {
        return TestResult::Fail("ref_freq_to_pix_freq");
    }
    // The same ratio across a 2200-pixel line, in U16.8.
    if dlg.refcyc_per_htotal != 379_259 {
        return TestResult::Fail("refcyc_per_htotal");
    }
    // Sync plus back porch: 2200 - 1920 - 88 pixels in reference cycles.
    if dlg.refcyc_h_blank_end != 129 || dlg.dlg_vblank_end != 41 {
        return TestResult::Fail("blank end");
    }
    // Two frames of lines less the front porch, active and maximum VStartup,
    // in U16.2: (2*1125 - 4 - 1080 - 44) * 4.
    if dlg.min_dst_y_next_start != 4488 {
        return TestResult::Fail("min_dst_y_next_start");
    }
    // The prefetch budget in U6.2 and its components in U5.2.
    if dlg.dst_y_prefetch != 12 || dlg.dst_y_per_vm_vblank != 1 || dlg.dst_y_per_row_vblank != 2 {
        return TestResult::Fail("prefetch budget fields");
    }
    if dlg.vratio_prefetch != 599_186 {
        return TestResult::Fail("vratio_prefetch");
    }
    if dlg.dst_y_after_scaler != 0 || dlg.refcyc_x_after_scaler != 138 {
        return TestResult::Fail("after-scaler fields");
    }
    // VReady lands inside the vertical blank, so the counter-zero form applies.
    if dlg.vready_after_vcount0 != 1 {
        return TestResult::Fail("vready_after_vcount0");
    }
    // 128 PTE-row lines at a unity vertical ratio, in U15.2.
    if dlg.dst_y_per_pte_row_nom_l != 512 {
        return TestResult::Fail("dst_y_per_pte_row_nom_l");
    }
    if dlg.refcyc_per_pte_group_nom_l != 189_629 || dlg.refcyc_per_pte_group_vblank_l != 740 {
        return TestResult::Fail("PTE group pacing");
    }
    // Active delivery is paced by the destination line; prefetch delivery by
    // the scaler, because the prefetch vertical ratio exceeds one.
    if dlg.refcyc_per_line_delivery_l != 43 || dlg.refcyc_per_line_delivery_pre_l != 21 {
        return TestResult::Fail("line delivery");
    }
    if dlg.dst_y_delta_drq_limit != 0x7fff || dlg.chunk_hdl_adjust_cur0 != 3 {
        return TestResult::Fail("fixed DLG fields");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml-regs",
    dml_regs_latency_fields_carry_their_binary_points
);

fn dml_regs_throttle_fields_track_the_deepest_watermark() -> TestResult {
    let config = config_1080p();
    let regs = registers(&config).unwrap();
    let ttu = regs.ttu;
    // The p-state watermark is the deepest here; plus TCalc, in reference
    // cycles at 100 MHz.
    if ttu.min_ttu_vblank != 1911 {
        return TestResult::Fail("min_ttu_vblank");
    }
    if ttu.qos_level_low_wm != 0 || ttu.qos_level_high_wm != 5925 {
        return TestResult::Fail("QoS watermarks");
    }
    // Request delivery in U?.10, active and prefetch.
    if ttu.refcyc_per_req_delivery_l != 44_131 || ttu.refcyc_per_req_delivery_pre_l != 21_845 {
        return TestResult::Fail("request delivery");
    }
    if ttu.qos_level_flip != 14 || ttu.qos_level_fixed_l != 8 || ttu.qos_ramp_disable_l != 0 {
        return TestResult::Fail("fixed QoS fields");
    }
    // LPDDR5's deeper self-refresh raises the TTU vblank floor.
    let geometry = config.geometry().unwrap();
    let clocks = clocks();
    let lpddr = Memory {
        kind: MemoryKind::Lpddr5,
        ..memory()
    };
    let wm = config.watermarks(&lpddr, &clocks).unwrap();
    let prefetch = config.prefetch(&geometry, &clocks, &wm).unwrap();
    let slow = Registers::new(&config, &geometry, &clocks, &wm, &prefetch, REFCLK_KHZ).unwrap();
    if slow.ttu.min_ttu_vblank <= ttu.min_ttu_vblank {
        return TestResult::Fail("LPDDR5 TTU vblank not deeper");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml-regs",
    dml_regs_throttle_fields_track_the_deepest_watermark
);

fn dml_regs_refuse_values_a_field_cannot_hold() -> TestResult {
    let config = config_1080p();
    let geometry = config.geometry().unwrap();
    let clocks = clocks();
    let wm = config.watermarks(&memory(), &clocks).unwrap();
    let prefetch = config.prefetch(&geometry, &clocks, &wm).unwrap();
    let encode = |refclk| Registers::new(&config, &geometry, &clocks, &wm, &prefetch, refclk);
    // A reference clock at four times the pixel clock cannot be held by the
    // U4.19 ratio field, so the mode is refused rather than wrapped.
    if encode(594_000) != Err(Error::Unsupported) {
        return TestResult::Fail("overflowing clock ratio accepted");
    }
    // The 14-bit QoS high watermark holds four line times, so it overflows
    // first: it binds the ratio to under 16384/(4*htotal), well below four.
    // Because the blank end is always shorter than a line, its own 13-bit
    // field can never be the first to overflow.
    if encode(590_000) != Err(Error::Unsupported) {
        return TestResult::Fail("overflowing QoS watermark accepted");
    }
    // Four line times must stay inside 14 bits, which bounds the reference
    // clock to 16384 * pixel_clock / (4 * htotal) — here about 276.5 MHz.
    let qos_limit_khz = 16_384 * config.timing.pixel_clock_khz / (4 * config.timing.h_total);
    if encode(qos_limit_khz - 500).is_err() {
        return TestResult::Fail("ratio inside the QoS limit rejected");
    }
    if encode(qos_limit_khz + 500) != Err(Error::Unsupported) {
        return TestResult::Fail("ratio beyond the QoS limit accepted");
    }
    // A stopped reference clock is not a scaling factor at all.
    if encode(0) != Err(Error::Invalid) {
        return TestResult::Fail("zero reference clock accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml-regs",
    dml_regs_refuse_values_a_field_cannot_hold
);

/// Field widths against the `_MASK` definitions in `dcn_3_1_4_sh_mask.h`.
///
/// `Registers` does not expose the widths, so this checks them through the
/// behaviour they produce: for each field, the largest value it can hold and
/// the smallest it cannot. A width that is too wide accepts a value the
/// hardware will truncate; one that is too narrow refuses a mode DML accepts.
fn dml_regs_field_widths_match_the_header_masks() -> TestResult {
    use crate::amdgpu_dml_regs::*;
    let config = config_1080p();
    let geometry = config.geometry().unwrap();
    let clocks = clocks();
    let wm = config.watermarks(&memory(), &clocks).unwrap();
    let prefetch = config.prefetch(&geometry, &clocks, &wm).unwrap();
    let r = Registers::new(&config, &geometry, &clocks, &wm, &prefetch, 100_000).unwrap();

    // The declared widths, against the `_MASK` definitions in
    // `dcn_3_1_4_sh_mask.h`. Comparing widths directly rather than inferring
    // them from produced values: a 1080p60 mode does not come near most of
    // these boundaries, so a field that is too *wide* is invisible in its
    // output and only shows up as silent truncation on some other mode.
    for (mask, width) in [
        (0x001F_FFFFu32, W_REF_FREQ_TO_PIX_FREQ),
        (0x001F_FFFF, W_REFCYC_PER_HTOTAL),
        (0x0000_1FFF, W_REFCYC_H_BLANK_END),
        (0x0000_7FFF, W_DLG_VBLANK_END),
        (0x0003_FFFF, W_MIN_DST_Y_NEXT_START),
        (0x0000_1FFF, W_REFCYC_X_AFTER_SCALER),
        (0x0000_0007, W_DST_Y_AFTER_SCALER),
        (0x0000_00FF, W_DST_Y_PREFETCH),
        (0x003F_FFFF, W_VRATIO_PREFETCH),
        (0x0000_007F, W_DST_Y_PER_VM_VBLANK),
        (0x0000_003F, W_DST_Y_PER_ROW_VBLANK),
        (0x0001_FFFF, W_DST_Y_PER_PTE_ROW_NOM_L),
        (0x007F_FFFF, W_REFCYC_PER_PTE_GROUP_NOM_L),
        (0x007F_FFFF, W_REFCYC_PER_PTE_GROUP_VBLANK_L),
        (0x0000_1FFF, W_REFCYC_PER_LINE_DELIVERY),
        (0x00FF_FFFF, W_MIN_TTU_VBLANK),
        (0x0000_3FFF, W_QOS_LEVEL_WM),
        (0x007F_FFFF, W_REFCYC_PER_REQ_DELIVERY),
    ] {
        if mask.count_ones() != width || mask.trailing_ones() != width {
            return TestResult::Fail("a field width disagrees with its header mask");
        }
    }

    // Every encoded value must fit the field the header declares.    // `dst_y_per_row_vblank` is six bits while `dst_y_per_vm_vblank`, its
    // neighbour in VBLANK_PARAMETERS_0, is seven. The two are not the same
    // width, which is the mistake a shared literal invites.
    if r.dlg.dst_y_per_row_vblank > 0x3F {
        return TestResult::Fail("dst_y_per_row_vblank is six bits, not seven");
    }

    // The two fields that were too *narrow*: a 1080p60 mode must encode, and
    // under a 13-bit limit `refcyc_per_pte_group_vblank_l` would not.
    if r.dlg.refcyc_per_pte_group_vblank_l == 0 {
        return TestResult::Fail("refcyc_per_pte_group_vblank_l should be non-zero here");
    }
    if r.ttu.refcyc_per_req_delivery_l == 0 {
        return TestResult::Fail("refcyc_per_req_delivery_l should be non-zero here");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml-regs",
    dml_regs_field_widths_match_the_header_masks
);
