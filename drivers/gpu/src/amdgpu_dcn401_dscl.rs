//! The DCN401 DSCL and HUBP viewport writes for one pipe's scaler
//! parameters, in Linux's order: dpp401_dscl_set_scaler_manual_scale (SPL
//! programming: `use_spl`, `prefer_easf`, no DSCL low-power gating) with
//! dpp401_dscl_set_lb, dpp401_dscl_find_lb_memory_config,
//! dpp401_dscl_set_manual_ratio_init, dpp401_dscl_program_isharp (iSHARP
//! off), dpp401_dscl_set_scl_filter / dpp401_dscl_set_scaler_filter and
//! dpp401_dscl_program_easf, then hubp401_set_viewport.
//!
//! Register numbers are pipe 0's (DSCL0, HUBP0); every write names the
//! fields Linux's REG_SET/REG_UPDATE call sets, so its mask is theirs.
//! A first programming after the pipe was stopped always loads the
//! coefficient RAM (Linux skips the load when the DPP still holds the same
//! filter; reloading it is equivalent). Pure: nothing here touches hardware.
use crate::amdgpu_dcn401_spl::{EasfDirection, Rect, Scaler, SCL_MODE_SCALING_444_BYPASS};
use alloc::vec::Vec;

pub const SCL_COEF_RAM_TAP_SELECT: u64 = 0xd06;
pub const SCL_COEF_RAM_TAP_DATA: u64 = 0xd07;
pub const SCL_MODE: u64 = 0xd08;
const SCL_TAP_CONTROL: u64 = 0xd09;
const DSCL_CONTROL: u64 = 0xd0a;
const DSCL_2TAP_CONTROL: u64 = 0xd0b;
const SCL_HORZ_FILTER_SCALE_RATIO: u64 = 0xd0d;
const SCL_HORZ_FILTER_INIT: u64 = 0xd0e;
const SCL_HORZ_FILTER_SCALE_RATIO_C: u64 = 0xd0f;
const SCL_HORZ_FILTER_INIT_C: u64 = 0xd10;
const SCL_VERT_FILTER_SCALE_RATIO: u64 = 0xd11;
const SCL_VERT_FILTER_INIT: u64 = 0xd12;
const SCL_VERT_FILTER_INIT_BOT: u64 = 0xd13;
const SCL_VERT_FILTER_SCALE_RATIO_C: u64 = 0xd14;
const SCL_VERT_FILTER_INIT_C: u64 = 0xd15;
const SCL_VERT_FILTER_INIT_BOT_C: u64 = 0xd16;
const DSCL_AUTOCAL: u64 = 0xd19;
const RECOUT_START: u64 = 0xd1e;
const RECOUT_SIZE: u64 = 0xd1f;
const MPC_SIZE: u64 = 0xd20;
const LB_DATA_FORMAT: u64 = 0xd21;
const LB_MEMORY_CTRL: u64 = 0xd22;
const EASF_H_MODE: u64 = 0xd28;
const EASF_V_MODE: u64 = 0xd29;
const SC_MODE: u64 = 0xd2a;
const SC_MATRIX_C0C1: u64 = 0xd2b;
const SC_MATRIX_C2C3: u64 = 0xd2c;
const EASF_H_EVENTAP_GAIN: u64 = 0xd2d;
const EASF_H_EVENTAP_REDUCE: u64 = 0xd2e;
const EASF_V_EVENTAP_GAIN: u64 = 0xd2f;
const EASF_V_EVENTAP_REDUCE: u64 = 0xd30;
const EASF_V_3TAP_CNTL1: u64 = 0xd31;
const EASF_H_BF_CNTL: u64 = 0xd35;
const EASF_H_BF_FINAL_MAX_MIN: u64 = 0xd36;
const EASF_V_BF_CNTL: u64 = 0xd37;
const EASF_V_BF_FINAL_MAX_MIN: u64 = 0xd38;
const EASF_H_BF1_PWL_SEG0: u64 = 0xd39;
const EASF_V_BF1_PWL_SEG0: u64 = 0xd41;
const EASF_H_BF3_PWL_SEG0: u64 = 0xd49;
const EASF_V_BF3_PWL_SEG0: u64 = 0xd4f;
pub const ISHARP_MODE: u64 = 0xd55;
pub const ISHARP_POWER: u64 = 0xd62;

/// HUBP primary/secondary viewport start and dimension, luma then chroma.
const PRI_VIEWPORT_START: u64 = 0x5e9;
const PRI_VIEWPORT_DIMENSION: u64 = 0x5eb;
const PRI_VIEWPORT_START_C: u64 = 0x5ec;
const PRI_VIEWPORT_DIMENSION_C: u64 = 0x5ed;
const SEC_VIEWPORT_START: u64 = 0x5ee;
const SEC_VIEWPORT_DIMENSION: u64 = 0x5ef;
const SEC_VIEWPORT_START_C: u64 = 0x5f0;
const SEC_VIEWPORT_DIMENSION_C: u64 = 0x5f1;

/// `enum dcn401_coef_filter_type_sel`.
pub const SCL_COEF_LUMA_VERT_FILTER: u32 = 0;
pub const SCL_COEF_LUMA_HORZ_FILTER: u32 = 1;
pub const SCL_COEF_CHROMA_VERT_FILTER: u32 = 2;
pub const SCL_COEF_CHROMA_HORZ_FILTER: u32 = 3;
/// SCL_MODE.SCL_COEF_RAM_SELECT and SCL_CHROMA_COEF_MODE; the swap writes
/// the opposite of SCL_COEF_RAM_SELECT_CURRENT (bit 12).
pub const COEF_RAM_SELECT: u32 = 0x100;
pub const CHROMA_COEF_MODE: u32 = 0x10000;
pub const COEF_RAM_SELECT_CURRENT: u32 = 0x1000;

/// One step of the programming sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Set `mask`'s fields of the register to `value`.
    Write { reg: u64, mask: u32, value: u32 },
    /// Wait until `mask`'s fields read `value`.
    Wait { reg: u64, mask: u32, value: u32 },
    /// dpp401_dscl_set_scaler_filter: SCL_COEF_RAM_TAP_SELECT for the filter
    /// type, then each word of [`coefficient_words`] to the auto-indexed
    /// SCL_COEF_RAM_TAP_DATA.
    Coefficients {
        filter_type: u32,
        taps: u32,
        filter: &'static [u16],
    },
    /// SCL_MODE: SCL_COEF_RAM_SELECT to the RAM not in use, and
    /// SCL_CHROMA_COEF_MODE: on for a YCbCr (4:2:0) plane, whose chroma
    /// filters were loaded too, off for RGB.
    SwapCoefficientRam { chroma: bool },
}

/// The SCL_COEF_RAM_TAP_DATA words of one filter load: 33 phases of tap
/// pairs, each even/odd coefficient with its write enable.
pub fn coefficient_words(taps: u32, filter: &[u16]) -> impl Iterator<Item = u32> + '_ {
    let taps = taps as usize;
    let pairs = taps.div_ceil(2);
    (0..33).flat_map(move |phase| {
        (0..pairs).map(move |pair| {
            let even = filter[phase * taps + 2 * pair];
            let odd = if pair * 2 + 1 < taps {
                filter[phase * taps + 2 * pair + 1]
            } else {
                0
            };
            (u32::from(even) & 0x3fff) | 0x8000 | (u32::from(odd) & 0x3fff) << 16 | 0x8000_0000
        })
    })
}

fn write(ops: &mut Vec<Op>, reg: u64, mask: u32, value: u32) {
    ops.push(Op::Write {
        reg,
        mask,
        value: value & mask,
    });
}
fn dims(r: Rect) -> u32 {
    (r.width as u32 & 0x3fff) | (r.height as u32 & 0x3fff) << 16
}
fn start(r: Rect) -> u32 {
    (r.x as u32 & 0xffff) | (r.y as u32) << 16
}

/// dpp401_dscl_program_isharp with iSHARP off: power the delta LUT, write
/// ISHARP_MODE's six fields as zero, let the LUT power down again.
fn isharp(ops: &mut Vec<Op>) {
    write(ops, ISHARP_POWER, 7, 4);
    ops.push(Op::Wait {
        reg: ISHARP_POWER,
        mask: 0x30,
        value: 0,
    });
    write(ops, ISHARP_MODE, 0x0fff_fa71, 0);
    write(ops, ISHARP_POWER, 7, 0);
}

/// dpp401_dscl_program_easf_v/h for one direction.
fn easf_direction(ops: &mut Vec<Op>, e: &EasfDirection, vertical: bool) {
    let (mode, cntl, reduce, gain, max_min, bf1, bf3) = if vertical {
        (
            EASF_V_MODE,
            EASF_V_BF_CNTL,
            EASF_V_EVENTAP_REDUCE,
            EASF_V_EVENTAP_GAIN,
            EASF_V_BF_FINAL_MAX_MIN,
            EASF_V_BF1_PWL_SEG0,
            EASF_V_BF3_PWL_SEG0,
        )
    } else {
        (
            EASF_H_MODE,
            EASF_H_BF_CNTL,
            EASF_H_EVENTAP_REDUCE,
            EASF_H_EVENTAP_GAIN,
            EASF_H_BF_FINAL_MAX_MIN,
            EASF_H_BF1_PWL_SEG0,
            EASF_H_BF3_PWL_SEG0,
        )
    };
    write(ops, mode, 0x3f11, e.en | e.ring << 4 | e.sharp_factor << 8);
    if e.en == 0 {
        return;
    }
    write(
        ops,
        cntl,
        0xfff3_0f01,
        e.bf1_en
            | e.bf2_mode << 8
            | e.bf3_mode << 16
            | e.bf2_flat1_gain << 20
            | e.bf2_flat2_gain << 24
            | e.bf2_roc_gain << 28,
    );
    if vertical {
        for (i, pair) in e.ringest_3tap.chunks_exact(2).enumerate() {
            write(
                ops,
                EASF_V_3TAP_CNTL1 + i as u64,
                u32::MAX,
                pair[0] | pair[1] << 16,
            );
        }
    }
    let [g1, g2] = e.ringest_eventap_reduceg;
    write(ops, reduce, u32::MAX, g1 | g2 << 16);
    let [g1, g2] = e.ringest_eventap_gain;
    write(ops, gain, u32::MAX, g1 | g2 << 16);
    let [maxa, maxb, mina, minb] = e.bf_max_min;
    write(
        ops,
        max_min,
        0x3f3f_3f3f,
        maxa | maxb << 8 | mina << 16 | minb << 24,
    );
    for (s, &[input, base, slope]) in e.bf1_pwl.iter().enumerate() {
        let (mask, slope) = if s == 7 {
            (0x3f7ff, 0)
        } else {
            (0x7ff3_f7ff, slope)
        };
        write(ops, bf1 + s as u64, mask, input | base << 12 | slope << 20);
    }
    for (s, &[input, base, slope]) in e.bf3_pwl.iter().enumerate() {
        let (mask, slope) = if s == 5 {
            (0x7ffff, 0)
        } else {
            (u32::MAX, slope)
        };
        write(ops, bf3 + s as u64, mask, input | base << 12 | slope << 19);
    }
}

/// dpp401_dscl_set_scaler_manual_scale for `s` (`alpha` is the plane's
/// per-pixel alpha, the line buffer's ALPHA_EN). A 4:2:0 plane is YCbCr:
/// dpp401_dscl_set_scl_filter's chroma coefficient mode loads its chroma
/// filters after the luma ones.
pub fn program(s: &Scaler, alpha: bool) -> Vec<Op> {
    let mut ops = Vec::with_capacity(96);
    let o = &mut ops;
    write(o, DSCL_AUTOCAL, 0x3303, 0);
    write(o, DSCL_CONTROL, 1, 0);
    write(o, RECOUT_START, 0x3fff_3fff, start(s.recout));
    write(o, RECOUT_SIZE, 0x3fff_3fff, dims(s.recout));
    write(
        o,
        MPC_SIZE,
        0x3fff_3fff,
        (s.mpc_size.0 as u32 & 0x3fff) | (s.mpc_size.1 as u32 & 0x3fff) << 16,
    );
    write(o, SCL_MODE, 7, s.dscl_mode);
    // dpp401_dscl_set_lb: float format, no interleave; 63 partitions.
    write(o, LB_DATA_FORMAT, 0x11, u32::from(alpha) << 4);
    write(
        o,
        LB_MEMORY_CTRL,
        0x3f03,
        s.lb_memory_config(alpha) | 63 << 8,
    );
    if s.dscl_mode == SCL_MODE_SCALING_444_BYPASS {
        write(o, EASF_V_MODE, 1, s.easf.v.en);
        write(o, EASF_H_MODE, 1, s.easf.h.en);
        isharp(o);
        return ops;
    }
    // No SCL_BLACK_OFFSET register on DCN401.
    let [h, v, h_c, v_c] = s.ratios;
    for (reg, ratio) in [
        (SCL_HORZ_FILTER_SCALE_RATIO, h),
        (SCL_VERT_FILTER_SCALE_RATIO, v),
        (SCL_HORZ_FILTER_SCALE_RATIO_C, h_c),
        (SCL_VERT_FILTER_SCALE_RATIO_C, v_c),
    ] {
        write(o, reg, 0x7ff_ffff, ratio);
    }
    let i = s.init;
    for (reg, (fraction, int)) in [
        (SCL_HORZ_FILTER_INIT, i.h),
        (SCL_HORZ_FILTER_INIT_C, i.h_c),
        (SCL_VERT_FILTER_INIT, i.v),
        (SCL_VERT_FILTER_INIT_BOT, i.v_bot),
        (SCL_VERT_FILTER_INIT_C, i.v_c),
        (SCL_VERT_FILTER_INIT_BOT_C, i.v_bot_c),
    ] {
        write(o, reg, 0x0fff_ffff, fraction | int << 24);
    }
    let [vt, ht, vt_c, ht_c] = s.taps;
    write(
        o,
        SCL_TAP_CONTROL,
        0x7777,
        vt | ht << 4 | vt_c << 8 | ht_c << 12,
    );
    isharp(o);
    // dpp401_dscl_set_scl_filter: DC's taps; no 2-tap sharpening.
    let [vt, ht, vt_c, ht_c] = s.dc_taps();
    let h2 = ht < 3 && ht_c < 3 && ht > 1 && ht_c > 1;
    let v2 = vt < 3 && vt_c < 3 && vt > 1 && vt_c > 1;
    write(
        o,
        DSCL_2TAP_CONTROL,
        0x0711_0711,
        u32::from(h2) | u32::from(v2) << 16,
    );
    let chroma = s.video.is_some();
    let (filter_h_c, filter_v_c) = if chroma {
        (s.filter_h_c, s.filter_v_c)
    } else {
        (None, None)
    };
    let any = s.filter_h.is_some()
        || s.filter_v.is_some()
        || filter_h_c.is_some()
        || filter_v_c.is_some();
    if !(v2 && h2) && any {
        if let Some(filter) = s.filter_h.filter(|_| !h2) {
            o.push(Op::Coefficients {
                filter_type: SCL_COEF_LUMA_HORZ_FILTER,
                taps: ht,
                filter,
            });
        }
        if let Some(filter) = s.filter_v.filter(|_| !v2) {
            o.push(Op::Coefficients {
                filter_type: SCL_COEF_LUMA_VERT_FILTER,
                taps: vt,
                filter,
            });
        }
        if let Some(filter) = filter_h_c.filter(|_| !h2) {
            o.push(Op::Coefficients {
                filter_type: SCL_COEF_CHROMA_HORZ_FILTER,
                taps: ht_c,
                filter,
            });
        }
        if let Some(filter) = filter_v_c.filter(|_| !v2) {
            o.push(Op::Coefficients {
                filter_type: SCL_COEF_CHROMA_VERT_FILTER,
                taps: vt_c,
                filter,
            });
        }
        o.push(Op::SwapCoefficientRam { chroma });
    }
    // dpp401_dscl_program_easf.
    let e = &s.easf;
    write(o, SC_MODE, 0x101, e.matrix_mode | e.ltonl_en << 8);
    write(
        o,
        SC_MATRIX_C0C1,
        u32::MAX,
        e.matrix_c[0] | e.matrix_c[1] << 16,
    );
    write(
        o,
        SC_MATRIX_C2C3,
        u32::MAX,
        e.matrix_c[2] | e.matrix_c[3] << 16,
    );
    easf_direction(o, &e.v, true);
    easf_direction(o, &e.h, false);
    ops
}

/// hubp401_set_viewport: (register, mask, value) for pipe 0.
pub fn viewport(s: &Scaler) -> [(u64, u32, u32); 8] {
    let (v, c) = (s.viewport, s.viewport_c);
    [
        (PRI_VIEWPORT_DIMENSION, 0x3fff_3fff, dims(v)),
        (PRI_VIEWPORT_START, u32::MAX, start(v)),
        (SEC_VIEWPORT_DIMENSION, 0x3fff_3fff, dims(v)),
        (SEC_VIEWPORT_START, u32::MAX, start(v)),
        (PRI_VIEWPORT_DIMENSION_C, 0x3fff_3fff, dims(c)),
        (PRI_VIEWPORT_START_C, u32::MAX, start(c)),
        (SEC_VIEWPORT_DIMENSION_C, 0x3fff_3fff, dims(c)),
        (SEC_VIEWPORT_START_C, u32::MAX, start(c)),
    ]
}
