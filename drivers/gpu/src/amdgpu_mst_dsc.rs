//! amdgpu_dm's MST DSC fairness search (amdgpu_dm_mst_types.c), ported to
//! be bit-exact against Linux built on the host (tests/dcn401_dsc/check.sh,
//! mst_harness.c): `compute_link` is compute_mst_dsc_configs_for_link with
//! increase_dsc_bpp, try_disable_dsc and set_dsc_configs_from_fairness_vars;
//! PBN from kbps_to_peak_pbn, the time slots drm_dp_atomic_find_time_slots
//! gives them and drm_dp_mst_atomic_check's slot and path limits.
use crate::amdgpu_dml::Timing;
use crate::amdgpu_dsc::{self, BwRange, DscConfig, DscSinkCaps, DscTiming, LinkEncoding};
use crate::dp_mst;
use crate::dp_mst_mgr::Sink;
use alloc::vec::Vec;

/// The topology's PBN check for a set of (end device, PBN) allocations.
pub type Fits<'a> = dyn Fn(&[(Sink, u16)]) -> bool + 'a;

/// PEAK_FACTOR_X1000 and the PBN FEC overhead multipliers.
const PEAK_FACTOR_X1000: u64 = 1006;
const FEC_8B10B_X1000: u64 = 1031;
const FEC_128B132B_X1000: u64 = 1000;

/// kbps_to_peak_pbn.
pub fn peak_pbn(kbps: u32, link: LinkEncoding) -> i32 {
    let fec = if link == LinkEncoding::Dp128b132b {
        FEC_128B132B_X1000
    } else {
        FEC_8B10B_X1000
    };
    let peak = u64::from(kbps) * PEAK_FACTOR_X1000 * fec / (1000 * 1000);
    (peak * 64).div_ceil(54 * 8 * 1000) as i32
}

/// kbps_from_pbn.
pub fn kbps_from_pbn(pbn: u32) -> u32 {
    (u64::from(pbn) * (1_000_000 / PEAK_FACTOR_X1000) * 8 * 54 / 64) as u32
}

/// The DSC view of an MST stream: 8-bpc RGB.
pub fn mst_dsc_timing(t: &Timing) -> DscTiming {
    DscTiming {
        pix_clk_100hz: t.pixel_clock_khz * 10,
        h_active: t.h_active,
        h_total: t.h_total,
        v_active: t.v_active,
        v_total: t.v_total,
        bpc: 8,
        encoding: amdgpu_dsc::Encoding::Rgb,
    }
}

/// The MST link the streams share, as the fairness search sees it.
#[derive(Clone, Copy, Debug)]
pub struct DscLink {
    /// dc_link_get_highest_encoding_format.
    pub encoding: LinkEncoding,
    /// dc_link_bandwidth_kbps of the trained (verified) link.
    pub kbps: u32,
    /// drm_dp_mst_update_slots: 63 on 8b/10b, 64 on 128b/132b.
    pub slots: u8,
    /// The board's highest DISPCLK, which dc_dsc_compute_config takes.
    pub max_dispclk_khz: u32,
}
impl DscLink {
    fn pbn_div(&self) -> u32 {
        dp_mst::pbn_div(self.kbps)
    }
}

/// One stream on the link: its end device, timing and decoder.
#[derive(Clone, Copy, Debug)]
pub struct DscStream {
    pub sink: Sink,
    pub timing: Timing,
    pub dsc: Option<DscSinkCaps>,
}

/// What `compute_link` gives a stream: its payload PBN and time slots and,
/// compressed, its DSC configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DscPayload {
    pub pbn: u16,
    pub slots: u8,
    pub dsc: Option<DscConfig>,
}

/// dsc_mst_fairness_params.
struct Params {
    range: BwRange,
    compression_possible: bool,
}

/// dsc_mst_fairness_vars.
#[derive(Clone, Copy, Debug)]
struct Vars {
    pbn: i32,
    dsc_enabled: bool,
    bpp_x16: u32,
}

/// The DSC configuration (no bpp) dc_dsc_compute_config gives a stream
/// (set_dsc_configs_from_fairness_vars' call with a zero target).
pub fn config(s: &DscStream, link: &DscLink) -> Option<DscConfig> {
    amdgpu_dsc::compute_config(
        s.dsc.as_ref()?,
        link.max_dispclk_khz,
        0,
        &mst_dsc_timing(&s.timing),
        link.encoding,
        false,
    )
}

/// bpp_x16_from_pbn: the bpp dc_dsc_compute_config picks for the bandwidth
/// of `pbn`; 0 when it finds none.
fn bpp_x16_from_pbn(s: &DscStream, link: &DscLink, pbn: i32) -> u32 {
    let kbps = (pbn as u64 * 994 * 8 * 54 / 64) as u32;
    s.dsc
        .as_ref()
        .and_then(|caps| {
            amdgpu_dsc::compute_config(
                caps,
                link.max_dispclk_khz,
                kbps,
                &mst_dsc_timing(&s.timing),
                link.encoding,
                false,
            )
        })
        .map_or(0, |c| c.bpp_x16)
}

/// The atomic check: drm_dp_mst_atomic_check_payload_alloc_limits (the
/// link's slots) and drm_dp_mst_atomic_check_mstb_bw_limit (`fits`, every
/// hop's PBN).
fn atomic_check(streams: &[DscStream], vars: &[Vars], link: &DscLink, fits: &Fits<'_>) -> bool {
    let div = link.pbn_div();
    let mut slots = 0u32;
    let mut alloc = Vec::new();
    for (s, v) in streams.iter().zip(vars) {
        let Ok(pbn) = u16::try_from(v.pbn) else {
            return false;
        };
        slots += dp_mst::time_slots(u32::from(pbn), div);
        alloc.push((s.sink, pbn));
    }
    slots <= u32::from(link.slots) && fits(&alloc)
}

/// compute_mst_dsc_configs_for_link for the streams on one MST link, in
/// Linux's order: every stream uncompressed (each at kbps_to_peak_pbn of
/// its uncompressed bandwidth); failing that every compressible stream at
/// its minimum bpp, which must fit; then increase_dsc_bpp hands out the
/// remaining time slots fairly, smallest slack first, and try_disable_dsc
/// turns compression off where the stream fits uncompressed, largest
/// saving first. `fits` is the topology's per-hop PBN check; `native` is
/// `config` where the display pipeline can run its shape (a stream it
/// cannot is not compressible). None when even the maximum compression
/// does not fit, or a stream would stay compressed without a bpp (Linux
/// would run it uncompressed in its compressed PBN).
pub fn compute_link(
    streams: &[DscStream],
    link: &DscLink,
    fits: &Fits<'_>,
    native: &dyn Fn(&DscStream) -> Option<DscConfig>,
) -> Option<Vec<DscPayload>> {
    let div = link.pbn_div();
    let div_trunc = (div >> 12) as i32;
    if streams.is_empty() || div == 0 {
        return None;
    }
    let params: Vec<Params> = streams
        .iter()
        .map(|s| {
            let t = mst_dsc_timing(&s.timing);
            let (min, max) = amdgpu_dsc::policy_bpp_x16(&t, link.encoding);
            let possible = native(s).is_some();
            let range = s
                .dsc
                .as_ref()
                .filter(|_| possible)
                .and_then(|caps| {
                    amdgpu_dsc::bandwidth_range(
                        caps,
                        link.max_dispclk_khz,
                        min,
                        max,
                        &t,
                        link.encoding,
                    )
                })
                .unwrap_or(BwRange {
                    min_bpp_x16: 0,
                    max_bpp_x16: 0,
                    min_kbps: 0,
                    max_kbps: 0,
                    stream_kbps: amdgpu_dsc::stream_kbps(&t, link.encoding),
                });
            Params {
                range,
                compression_possible: possible,
            }
        })
        .collect();
    // Try no compression.
    let mut vars: Vec<Vars> = params
        .iter()
        .map(|p| Vars {
            pbn: peak_pbn(p.range.stream_kbps, link.encoding),
            dsc_enabled: false,
            bpp_x16: 0,
        })
        .collect();
    if !atomic_check(streams, &vars, link, fits) {
        // Try max compression.
        for (v, p) in vars.iter_mut().zip(&params) {
            if p.compression_possible {
                *v = Vars {
                    pbn: peak_pbn(p.range.min_kbps, link.encoding),
                    dsc_enabled: true,
                    bpp_x16: p.range.min_bpp_x16,
                };
            }
        }
        if !atomic_check(streams, &vars, link, fits) {
            return None;
        }
        increase_dsc_bpp(streams, &params, &mut vars, link, div_trunc, fits);
        try_disable_dsc(streams, &params, &mut vars, link, fits);
    }
    // set_dsc_configs_from_fairness_vars.
    streams
        .iter()
        .zip(&vars)
        .map(|(s, v)| {
            let dsc = if v.dsc_enabled {
                let cfg = native(s).map(|c| DscConfig {
                    bpp_x16: v.bpp_x16,
                    ..c
                });
                // A stream left compressed without a bpp has no PPS.
                if cfg.is_none_or(|c| c.bpp_x16 == 0) {
                    return None;
                }
                cfg
            } else {
                None
            };
            let pbn = u16::try_from(v.pbn).ok()?;
            Some(DscPayload {
                pbn,
                slots: dp_mst::time_slots(u32::from(pbn), div) as u8,
                dsc,
            })
        })
        .collect()
}

/// increase_dsc_bpp: each compressed stream, smallest slack first, takes
/// its fair share of the free time slots (Linux counts 63 even on
/// 128b/132b) or, when its slack is smaller, all of its slack (its maximum
/// bpp); a share that breaks the atomic check is given back.
fn increase_dsc_bpp(
    streams: &[DscStream],
    params: &[Params],
    vars: &mut [Vars],
    link: &DscLink,
    div_trunc: i32,
    fits: &Fits<'_>,
) {
    let n = vars.len();
    let mut slack = alloc::vec![0i32; n];
    let mut increased = alloc::vec![true; n];
    let mut remaining = 0i32;
    for i in 0..n {
        if vars[i].dsc_enabled {
            slack[i] = peak_pbn(params[i].range.max_kbps, link.encoding) - vars[i].pbn;
            increased[i] = false;
            remaining += 1;
        }
    }
    while remaining > 0 {
        let mut next = None;
        for i in 0..n {
            if !increased[i] && next.is_none_or(|j: usize| slack[j] > slack[i]) {
                next = Some(i);
            }
        }
        let Some(next) = next else { break };
        let used: i32 = vars
            .iter()
            .map(|v| (v.pbn + div_trunc - 1) / div_trunc)
            .sum();
        let fair = (63 - used) / remaining * div_trunc;
        if slack[next] > fair {
            vars[next].pbn += fair;
            if atomic_check(streams, vars, link, fits) {
                vars[next].bpp_x16 = bpp_x16_from_pbn(&streams[next], link, vars[next].pbn);
            } else {
                vars[next].pbn -= fair;
            }
        } else {
            vars[next].pbn += slack[next];
            if atomic_check(streams, vars, link, fits) {
                vars[next].bpp_x16 = params[next].range.max_bpp_x16;
            } else {
                vars[next].pbn -= slack[next];
            }
        }
        increased[next] = true;
        remaining -= 1;
    }
}

/// try_disable_dsc: each stream compressed at its maximum bpp, largest
/// bandwidth saving first, goes uncompressed if the link still fits.
fn try_disable_dsc(
    streams: &[DscStream],
    params: &[Params],
    vars: &mut [Vars],
    link: &DscLink,
    fits: &Fits<'_>,
) {
    let n = vars.len();
    let mut increase = alloc::vec![0i32; n];
    let mut tried = alloc::vec![true; n];
    let mut remaining = 0;
    for i in 0..n {
        if vars[i].dsc_enabled && vars[i].bpp_x16 == params[i].range.max_bpp_x16 {
            increase[i] = params[i]
                .range
                .stream_kbps
                .wrapping_sub(params[i].range.max_kbps) as i32;
            tried[i] = false;
            remaining += 1;
        }
    }
    while remaining > 0 {
        let mut next = None;
        for i in 0..n {
            if !tried[i] && next.is_none_or(|j: usize| increase[j] < increase[i]) {
                next = Some(i);
            }
        }
        let Some(next) = next else { break };
        let saved = vars[next].pbn;
        vars[next].pbn = peak_pbn(params[next].range.stream_kbps, link.encoding);
        if atomic_check(streams, vars, link, fits) {
            vars[next].dsc_enabled = false;
            vars[next].bpp_x16 = 0;
        } else {
            vars[next].pbn = saved;
        }
        tried[next] = true;
        remaining -= 1;
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_mst_dsc_tests.rs"]
mod tests;
