//! DCN 3.1.4 HUBP request, latency and throttle register encoding: the RQ, DLG
//! and TTU register values Linux derives in `display_rq_dlg_calc_314.c` from the
//! mode math in [`crate::amdgpu_dml`].
//!
//! Every field here has a fixed hardware width and an implied binary point, and
//! a value that does not fit is refused rather than truncated: a wrapped latency
//! register does not degrade the picture, it underflows the pipe. The same
//! single-plane scope applies as in the mode math — packed linear RGB, no DCC,
//! no chroma, no ODM combine, no DSC, no cursor and no immediate flip — so every
//! meta, page-table-frame, flip, chroma and XFC field is left at the value DML
//! produces for an absent surface, which this module states explicitly instead
//! of silently omitting.
use crate::amdgpu_dml::{
    ceil_multiple, log2_floor, ClockState, Config, Error, Fx, Geometry, Prefetch, Watermarks,
    CHUNK_BYTES, DPTE_BUFFER_IN_PTE_REQS_LUMA, DPTE_GROUP_BYTES, GPUVM_MIN_PAGE_BYTES,
    META_CHUNK_BYTES, MIN_CHUNK_BYTES, MIN_META_CHUNK_BYTES, MPTE_GROUP_BYTES,
};

/// Request geometry: how a linear surface is divided into 64-byte page-table
/// requests and the groups the DLG paces them in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requests {
    pub dpte_req_width: u64,
    pub dpte_row_height: u64,
    pub dpte_row_width_ub: u64,
    pub dpte_req_per_row_ub: u64,
    pub dpte_groups_per_row_ub: u64,
    /// 256-byte requests across one swath.
    pub req_per_swath_ub: u64,
}
/// RQ registers (`DCHUBP_REQ_SIZE_CONFIG`, `DCN_EXPANSION_MODE`). All of these
/// are log2-encoded sizes with a per-field bias.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RequestRegisters {
    pub chunk_size: u32,
    pub min_chunk_size: u32,
    pub meta_chunk_size: u32,
    pub min_meta_chunk_size: u32,
    pub dpte_group_size: u32,
    pub mpte_group_size: u32,
    pub swath_height: u32,
    pub pte_row_height_linear: u32,
    pub drq_expansion_mode: u32,
    pub prq_expansion_mode: u32,
    pub mrq_expansion_mode: u32,
    pub crq_expansion_mode: u32,
}
/// DLG registers. Fields this configuration cannot produce — every meta chunk,
/// page-table-frame, flip and chroma counterpart — stay zero, which is what DML
/// yields when the corresponding surface is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LatencyRegisters {
    /// U4.19 ratio of the DCHUB reference clock to the pixel clock.
    pub ref_freq_to_pix_freq: u32,
    /// U16.8 reference cycles per horizontal total.
    pub refcyc_per_htotal: u32,
    pub refcyc_h_blank_end: u32,
    pub dlg_vblank_end: u32,
    /// U16.2 destination line at which the next frame's fetch may begin.
    pub min_dst_y_next_start: u32,
    pub refcyc_x_after_scaler: u32,
    pub dst_y_after_scaler: u32,
    /// U6.2 prefetch budget, and its U5.2 page-table components.
    pub dst_y_prefetch: u32,
    pub dst_y_per_vm_vblank: u32,
    pub dst_y_per_row_vblank: u32,
    /// U4.19 prefetch vertical ratio.
    pub vratio_prefetch: u32,
    pub vready_after_vcount0: u32,
    /// U15.2 destination lines per page-table row.
    pub dst_y_per_pte_row_nom_l: u32,
    pub refcyc_per_pte_group_nom_l: u32,
    pub refcyc_per_pte_group_vblank_l: u32,
    pub refcyc_per_line_delivery_l: u32,
    pub refcyc_per_line_delivery_pre_l: u32,
    pub dst_y_delta_drq_limit: u32,
    pub chunk_hdl_adjust_cur0: u32,
    pub dst_y_offset_cur0: u32,
}
/// TTU registers (`DCN_TTU_QOS_WM`, `DCN_SURF0_TTU_CNTL0/1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ThrottleRegisters {
    pub min_ttu_vblank: u32,
    pub qos_level_low_wm: u32,
    pub qos_level_high_wm: u32,
    pub qos_level_flip: u32,
    /// U?.10 reference cycles per request delivery.
    pub refcyc_per_req_delivery_l: u32,
    pub refcyc_per_req_delivery_pre_l: u32,
    pub qos_level_fixed_l: u32,
    pub qos_ramp_disable_l: u32,
}
/// The complete per-HUBP register set for one plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub requests: Requests,
    pub rq: RequestRegisters,
    pub dlg: LatencyRegisters,
    pub ttu: ThrottleRegisters,
}

/// Encode `value` into a field of `bits` whole bits with `frac` fractional bits,
/// truncating toward zero as the hardware format does but refusing a value the
/// field cannot represent.
fn field(value: Fx, frac: u32, bits: u32) -> Result<u32, Error> {
    let scaled = value.times(Fx::int(1i64 << frac)).floor();
    if scaled < 0 || scaled >= 1i64 << bits {
        return Err(Error::Unsupported);
    }
    Ok(scaled as u32)
}
fn whole(value: u64, bits: u32) -> Result<u32, Error> {
    if value >= 1u64 << bits {
        return Err(Error::Unsupported);
    }
    Ok(value as u32)
}

impl Requests {
    /// The linear page-table request geometry. A 64-byte request returns eight
    /// PTEs, each covering one line of a 4 KiB virtual page, so the request is
    /// `8 * 4096 / bytes_per_pixel` pixels wide and one line tall.
    pub fn new(config: &Config, geometry: &Geometry) -> Result<Self, Error> {
        let bytes_per_pixel = geometry.bytes_per_pixel;
        let vmpg_width = GPUVM_MIN_PAGE_BYTES / bytes_per_pixel;
        let dpte_req_width = vmpg_width * 8;
        let pitch = config.plane.pitch as u64;
        // The PTE row height is how much pitch the request buffer can hold,
        // rounded down to a power of two. DML asserts at least eight lines and
        // caps at 128; a pitch that violates the floor is not supported here.
        let rows = DPTE_BUFFER_IN_PTE_REQS_LUMA * dpte_req_width / pitch.max(1);
        let log2_row_height = log2_floor(rows);
        if log2_row_height < 3 {
            return Err(Error::Unsupported);
        }
        let log2_row_height = log2_row_height.min(7);
        let dpte_row_height = 1u64 << log2_row_height;
        // Linear PTE requests wrap at the pitch, so the row's upper bound is
        // the whole pitch-by-row-height block rounded out to a request.
        let dpte_row_width_ub = ceil_multiple(
            pitch.saturating_mul(dpte_row_height).saturating_sub(1),
            dpte_req_width,
        ) + dpte_req_width;
        let dpte_req_per_row_ub = dpte_row_width_ub / dpte_req_width;
        let group_length = DPTE_GROUP_BYTES / 64;
        let dpte_group_width = group_length * dpte_req_width;
        let dpte_groups_per_row_ub = dpte_row_width_ub.div_ceil(dpte_group_width);
        Ok(Self {
            dpte_req_width,
            dpte_row_height,
            dpte_row_width_ub,
            dpte_req_per_row_ub,
            dpte_groups_per_row_ub,
            req_per_swath_ub: geometry.swath_width_ub / geometry.block_width_256,
        })
    }
}

/// `get_refcyc_per_delivery`. Below a vertical ratio of one the pipe is paced by
/// the destination line; above it, by how fast the scaler can take pixels.
fn refcyc_per_delivery(
    refclk_mhz: Fx,
    pixel_clock_mhz: Fx,
    recout_width: u64,
    v_ratio: Fx,
    hscale_pixel_rate: Fx,
    delivery_width: u64,
    req_per_swath_ub: u64,
) -> Fx {
    if v_ratio <= Fx::ONE {
        refclk_mhz
            .times(Fx::int(recout_width as i64))
            .over(pixel_clock_mhz)
            .over(Fx::int(req_per_swath_ub as i64))
    } else {
        refclk_mhz
            .times(Fx::int(delivery_width as i64))
            .over(hscale_pixel_rate)
            .over(Fx::int(req_per_swath_ub as i64))
    }
}

impl Registers {
    /// Encode the RQ, DLG and TTU registers for this plane.
    ///
    /// `dchub_refclk_khz` is the DCHUB reference clock every DLG and TTU field
    /// is expressed in. It comes from the VBIOS firmware-info crystal frequency,
    /// not from any display clock, and getting it wrong rescales every latency
    /// register at once.
    pub fn new(
        config: &Config,
        geometry: &Geometry,
        clocks: &ClockState,
        watermarks: &Watermarks,
        prefetch: &Prefetch,
        dchub_refclk_khz: u32,
    ) -> Result<Self, Error> {
        if dchub_refclk_khz == 0 {
            return Err(Error::Invalid);
        }
        let requests = Requests::new(config, geometry)?;
        let refclk = Fx::ratio(dchub_refclk_khz as i64, 1000);
        let pixel_clock = Fx::ratio(config.timing.pixel_clock_khz as i64, 1000);
        let h_total = config.timing.h_total as u64;
        let ref_to_pix = refclk.over(pixel_clock);
        // DML asserts this ratio stays below four; the U4.19 field cannot hold
        // more, and a pixel clock that low is not a mode this path supports.
        if ref_to_pix >= Fx::int(4) {
            return Err(Error::Unsupported);
        }

        let rq = RequestRegisters {
            chunk_size: log2_floor(CHUNK_BYTES) - 10,
            min_chunk_size: log2_floor(MIN_CHUNK_BYTES) - 8 + 1,
            meta_chunk_size: log2_floor(META_CHUNK_BYTES) - 10,
            min_meta_chunk_size: log2_floor(MIN_META_CHUNK_BYTES) - 6 + 1,
            dpte_group_size: log2_floor(DPTE_GROUP_BYTES) - 6,
            mpte_group_size: log2_floor(MPTE_GROUP_BYTES) - 6,
            swath_height: log2_floor(geometry.swath_height),
            pte_row_height_linear: log2_floor(requests.dpte_row_height) - 3,
            // An 8 KiB chunk is below the 32 KiB threshold that disables
            // expansion, so the detile request queue expands by two.
            drq_expansion_mode: 2,
            prq_expansion_mode: 1,
            mrq_expansion_mode: 1,
            crq_expansion_mode: 1,
        };

        // MIN_DST_Y_NEXT_START follows DML's final pass, which uses the maximum
        // VStartup rather than the one the prefetch search settled on. A larger
        // VStartup moves the next frame's fetch earlier, so this is the
        // conservative choice of the two.
        let min_dst_y_next_start = (config.timing.v_total as u64 + config.timing.v_total as u64)
            .saturating_sub(config.timing.v_front_porch as u64)
            .saturating_sub(config.timing.v_active as u64)
            .saturating_sub(prefetch.max_v_startup as u64);
        let vready_sum = (prefetch.v_ready_offset_pix
            + prefetch.v_update_width_pix
            + prefetch.v_update_offset_pix) as u64;
        let vready_after_vcount0 = u32::from(
            Fx::int(prefetch.v_startup as i64).minus(Fx::ratio(vready_sum as i64, h_total as i64))
                <= Fx::int(config.timing.v_blank_end() as i64),
        );

        // The scaler's horizontal consumption rate, which paces delivery once
        // the vertical ratio exceeds one.
        let min_hratio_fact = if geometry.h_ratio <= Fx::ONE {
            Fx::int(2)
        } else if config.plane.h_taps <= 6 {
            geometry.h_ratio.times(Fx::int(2)).min(Fx::int(4))
        } else {
            geometry.h_ratio.min(Fx::int(4))
        };
        let hscale_pixel_rate = min_hratio_fact.times(Fx::ratio(clocks.dppclk_khz as i64, 1000));

        let line_delivery = refcyc_per_delivery(
            refclk,
            pixel_clock,
            config.timing.h_active as u64,
            geometry.v_ratio,
            hscale_pixel_rate,
            geometry.swath_width_ub,
            requests.req_per_swath_ub,
        );
        let line_delivery_pre = refcyc_per_delivery(
            refclk,
            pixel_clock,
            config.timing.h_active as u64,
            prefetch.v_ratio_prefetch,
            hscale_pixel_rate,
            config.plane.viewport_width as u64,
            requests.req_per_swath_ub,
        );
        // Request delivery differs from line delivery only in the width it
        // paces by, which matters only above a vertical ratio of one.
        let req_delivery = refcyc_per_delivery(
            refclk,
            pixel_clock,
            config.timing.h_active as u64,
            geometry.v_ratio,
            hscale_pixel_rate,
            config.plane.viewport_width as u64,
            requests.req_per_swath_ub,
        );
        let req_delivery_pre = refcyc_per_delivery(
            refclk,
            pixel_clock,
            config.timing.h_active as u64,
            prefetch.v_ratio_prefetch,
            hscale_pixel_rate,
            config.plane.viewport_width as u64,
            requests.req_per_swath_ub,
        );

        let pte_row_lines = Fx::int(requests.dpte_row_height as i64).over(geometry.v_ratio);
        let groups_per_row = Fx::int(requests.dpte_groups_per_row_ub as i64);
        let dlg = LatencyRegisters {
            ref_freq_to_pix_freq: field(ref_to_pix, 19, 23)?,
            refcyc_per_htotal: field(ref_to_pix.times(Fx::int(h_total as i64)), 8, 24)?,
            refcyc_h_blank_end: field(
                ref_to_pix.times(Fx::int(config.timing.h_blank_end() as i64)),
                0,
                13,
            )?,
            dlg_vblank_end: whole(config.timing.v_blank_end() as u64, 15)?,
            min_dst_y_next_start: field(Fx::int(min_dst_y_next_start as i64), 2, 18)?,
            refcyc_x_after_scaler: field(
                ref_to_pix.times(Fx::int(prefetch.dst_x_after_scaler as i64)),
                0,
                13,
            )?,
            dst_y_after_scaler: whole(prefetch.dst_y_after_scaler as u64, 3)?,
            dst_y_prefetch: field(prefetch.dst_y_prefetch, 2, 8)?,
            dst_y_per_vm_vblank: field(prefetch.dst_y_per_vm_vblank, 2, 7)?,
            dst_y_per_row_vblank: field(prefetch.dst_y_per_row_vblank, 2, 7)?,
            vratio_prefetch: field(prefetch.v_ratio_prefetch, 19, 23)?,
            vready_after_vcount0,
            dst_y_per_pte_row_nom_l: field(pte_row_lines, 2, 17)?,
            refcyc_per_pte_group_nom_l: field(
                pte_row_lines
                    .times(Fx::int(h_total as i64))
                    .times(ref_to_pix)
                    .over(groups_per_row),
                0,
                23,
            )?,
            refcyc_per_pte_group_vblank_l: field(
                prefetch
                    .dst_y_per_row_vblank
                    .times(Fx::int(h_total as i64))
                    .times(ref_to_pix)
                    .over(groups_per_row),
                0,
                13,
            )?,
            refcyc_per_line_delivery_l: field(line_delivery, 0, 13)?,
            refcyc_per_line_delivery_pre_l: field(line_delivery_pre, 0, 13)?,
            // The delta-DRQ limit is disabled, and the cursor handles keep
            // DML's fixed values even with no cursor surface programmed.
            dst_y_delta_drq_limit: 0x7fff,
            chunk_hdl_adjust_cur0: 3,
            dst_y_offset_cur0: 0,
        };

        // MinTTUVBlank at prefetch mode 0: the deepest of the three watermarks
        // plus the DCHUB calculation time.
        let min_ttu_vblank = prefetch.t_calc_us.plus(
            watermarks.pstate_change_us.max(
                watermarks
                    .stutter_enter_plus_exit_us
                    .max(watermarks.urgent_us),
            ),
        );
        let ttu = ThrottleRegisters {
            min_ttu_vblank: field(min_ttu_vblank.times(refclk), 0, 24)?,
            qos_level_low_wm: 0,
            qos_level_high_wm: field(
                Fx::int(4).times(Fx::int(h_total as i64)).times(ref_to_pix),
                0,
                14,
            )?,
            qos_level_flip: 14,
            refcyc_per_req_delivery_l: field(req_delivery, 10, 22)?,
            refcyc_per_req_delivery_pre_l: field(req_delivery_pre, 10, 22)?,
            qos_level_fixed_l: 8,
            qos_ramp_disable_l: 0,
        };

        Ok(Self {
            requests,
            rq,
            dlg,
            ttu,
        })
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dml_regs_tests.rs"]
mod tests;
