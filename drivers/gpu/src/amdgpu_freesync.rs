//! Variable refresh (FreeSync / DP Adaptive-Sync) policy shared by the native
//! AMD display owners: the sink's refresh range, whether a mode may vary its
//! refresh, and the vertical totals the timing generator stretches between.
//! Linux: drm_edid.c `drm_get_monitor_range`, amdgpu_dm
//! `amdgpu_dm_update_freesync_caps` / `amdgpu_dm_get_freesync_config_for_crtc`,
//! and modules/freesync `mod_freesync_build_vrr_params` /
//! `mod_freesync_calc_v_total_from_refresh`. Integer arithmetic only.
//!
//! Supported: DP SST sinks whose EDID declares a "range limits only" range
//! and whose DPCD sets MSA_TIMING_PAR_IGNORED. Gaps (not implemented, the sink
//! is then not VRR-capable here): HDMI FreeSync (it needs the AMD VSDB, as
//! Linux does), DisplayID adaptive-sync ranges (eDP), DP MST, PCON
//! whitelists, MCCS (DDC/CI) FreeSync control, below-the-range low framerate
//! compensation (BTR/LFC) and the AMD FreeSync VSIF/SDP infopacket.
use crate::amdgpu_dml::Timing;

/// freesync.c MIN_REFRESH_RANGE: narrower ranges stay at fixed refresh.
pub const MIN_REFRESH_RANGE_HZ: u32 = 10;
/// dcn401_resource.c `dc->caps.max_v_total`: the 15-bit OTG field.
pub const MAX_V_TOTAL: u32 = (1 << 15) - 1;

/// drm_display_info.monitor_range: the EDID's vertical rate limits in Hz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonitorRange {
    pub min_vfreq: u16,
    pub max_vfreq: u16,
}

/// The display descriptor tag of a Monitor Range Limits descriptor.
const RANGE_DESCRIPTOR: u8 = 0xfd;
/// DRM_EDID_RANGE_LIMITS_ONLY_FLAG: the only variant promising every timing
/// inside the range, so the only one usable for VRR.
const RANGE_LIMITS_ONLY: u8 = 0x01;
/// DRM_EDID_RANGE_OFFSET_{MIN,MAX}_VFREQ (EDID 1.4): add 255 Hz.
const OFFSET_MIN_VFREQ: u8 = 1 << 0;
const OFFSET_MAX_VFREQ: u8 = 1 << 1;
/// DRM_EDID_FEATURE_CONTINUOUS_FREQ.
const CONTINUOUS_FREQ: u8 = 1 << 0;

/// drm_get_monitor_range over a whole EDID (base block then extensions):
/// EDID 1.4 with continuous frequency, every 18-byte detailed block (the base
/// block's four, a CTA-861 extension's DTD area, a VTB extension's), the
/// last matching "range limits only" descriptor winning, with the 1.4 +255
/// offsets. None when no descriptor qualifies (Linux's 0..0).
pub fn monitor_range(edid: &[u8]) -> Option<MonitorRange> {
    let base = edid.get(..128)?;
    let revision = base[0x13];
    if revision < 4 || base[0x18] & CONTINUOUS_FREQ == 0 {
        return None;
    }
    let mut range = None;
    let mut visit = |d: &[u8]| {
        // is_display_descriptor: pixel clock 0, pad1 0, the tag.
        if d.len() < 18 || d[0] != 0 || d[1] != 0 || d[2] != 0 || d[3] != RANGE_DESCRIPTOR {
            return;
        }
        if d[10] != RANGE_LIMITS_ONLY {
            return;
        }
        let mut r = MonitorRange {
            min_vfreq: u16::from(d[5]),
            max_vfreq: u16::from(d[6]),
        };
        // revision >= 4 already holds.
        if d[4] & OFFSET_MIN_VFREQ != 0 {
            r.min_vfreq += 255;
        }
        if d[4] & OFFSET_MAX_VFREQ != 0 {
            r.max_vfreq += 255;
        }
        range = Some(r);
    };
    for i in 0..4 {
        let at = 54 + 18 * i;
        visit(&base[at..at + 18]);
    }
    // drm_edid_block_count: the declared extensions, limited by the size.
    let blocks = (usize::from(base[0x7e]) + 1).min(edid.len() / 128);
    for ext in edid.chunks_exact(128).take(blocks).skip(1) {
        match ext[0] {
            // cea_for_each_detailed_block
            0x02 => {
                let d = usize::from(ext[2]);
                if !(4..=127).contains(&d) {
                    continue;
                }
                for i in 0..(127 - d) / 18 {
                    visit(&ext[d + 18 * i..d + 18 * i + 18]);
                }
            }
            // vtb_for_each_detailed_block
            0x10 if ext[1] == 1 => {
                for i in 0..usize::from(ext[2]).min(6) {
                    visit(&ext[5 + 18 * i..5 + 18 * i + 18]);
                }
            }
            _ => {}
        }
    }
    range
}

/// DP_DOWN_STREAM_PORT_COUNT (DPCD 0x007) MSA_TIMING_PAR_IGNORED: the sink
/// can run without the MSA's timing (dpcd_caps.allow_invalid_MSA_timing_param).
pub const DPCD_MSA_TIMING_PAR_IGNORED: u8 = 1 << 6;
/// DP_DOWNSPREAD_CTRL (DPCD 0x107) and its IGNORE_MSA_TIMING_PARAM bit.
pub const DPCD_DOWNSPREAD_CTRL: u32 = 0x107;
pub const DPCD_IGNORE_MSA_TIMING_PARAM: u8 = 1 << 7;

/// A FreeSync-capable sink's refresh range (amdgpu_dm_connector min/max_vfreq
/// with freesync_capable set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrrRange {
    pub min_hz: u16,
    pub max_hz: u16,
}

impl VrrRange {
    /// amdgpu_dm_get_freesync_config_for_crtc's vrr_supported: the mode's
    /// drm_mode_vrefresh lies within the sink's range.
    pub fn supports(self, timing: &Timing) -> bool {
        let hz = vrefresh(timing);
        hz != 0 && hz >= u32::from(self.min_hz) && hz <= u32::from(self.max_hz)
    }
}

/// amdgpu_dm_update_freesync_caps for a DP SST sink: the EDID range when the
/// DPCD allows invalid MSA timing and the range is more than 10 Hz wide.
/// HDMI (AMD VSDB) and DisplayID ranges are not implemented.
pub fn dp_sst_caps(edid: &[u8], dpcd: &[u8; 16]) -> Option<VrrRange> {
    if dpcd[7] & DPCD_MSA_TIMING_PAR_IGNORED == 0 {
        return None;
    }
    let r = monitor_range(edid)?;
    // `max_vfreq - min_vfreq > 10` in Linux's int arithmetic.
    (i32::from(r.max_vfreq) - i32::from(r.min_vfreq) > 10).then_some(VrrRange {
        min_hz: r.min_vfreq,
        max_hz: r.max_vfreq,
    })
}

/// drm_mode_vrefresh for a progressive mode: the rounded refresh in Hz.
pub fn vrefresh(t: &Timing) -> u32 {
    let total = u64::from(t.h_total) * u64::from(t.v_total);
    if total == 0 {
        return 0;
    }
    let num = u64::from(t.pixel_clock_khz) * 1000;
    u32::try_from((num + total / 2) / total).unwrap_or(0)
}

/// The vertical totals DRR stretches between (`dc_crtc_timing_adjust`
/// v_total_min/max), in lines, not yet minus one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Drr {
    pub v_total_min: u32,
    pub v_total_max: u32,
}

/// mod_freesync_calc_nominal_field_rate: pix_clk_100hz * 1e8 / (h * v), uHz.
fn nominal_uhz(t: &Timing) -> Option<u64> {
    let p100 = u64::from(t.pixel_clock_khz).checked_mul(10)?;
    let total = u64::from(t.h_total).checked_mul(u64::from(t.v_total))?;
    p100.checked_mul(100_000_000)?.checked_div(total)
}

/// mod_freesync_calc_v_total_from_refresh. `stream_min_uhz`/`stream_max_uhz`
/// are dc_crtc_timing's min/max_refresh_in_uhz, which amdgpu_dm leaves zero:
/// every target then takes the round-up branch. At or below the stream
/// minimum it rounds down; strictly inside it rounds to nearest. Never below
/// the nominal total. None on arithmetic overflow (Linux would truncate).
pub fn calc_v_total_from_refresh(
    t: &Timing,
    refresh_uhz: u64,
    stream_min_uhz: u64,
    stream_max_uhz: u64,
) -> Option<u32> {
    if refresh_uhz == 0 {
        return Some(t.v_total);
    }
    if t.h_total == 0 {
        return None;
    }
    // frame_duration_in_ns is an unsigned int in Linux.
    let frame_ns = u64::from(u32::try_from(1_000_000_000_000_000u64 / refresh_uhz).ok()?);
    let lines_e6 = frame_ns.checked_mul(u64::from(t.pixel_clock_khz))? / u64::from(t.h_total);
    let v = if refresh_uhz <= stream_min_uhz {
        lines_e6 / 1_000_000
    } else if refresh_uhz >= stream_max_uhz {
        lines_e6.checked_add(999_999)? / 1_000_000
    } else {
        lines_e6.checked_add(500_000)? / 1_000_000
    };
    Some(u32::try_from(v).ok()?.max(t.v_total))
}

/// mod_freesync_build_vrr_params for VRR_STATE_ACTIVE_VARIABLE on DCN401
/// (max_v_total 32767, vtotal_limited_by_fp2): the sink range limited below
/// by what the hardware can stretch to and above by the mode's nominal
/// refresh (with Linux's exact-2x rule), then v_total_min from the maximum
/// and v_total_max from the minimum refresh. None (fixed refresh, Linux's
/// INACTIVE totals) when the remaining range is under 10 Hz, the mode is not
/// within the sink's range, or a total exceeds max_v_total (where
/// dc_stream_adjust_vmin_vmax refuses).
pub fn drr(t: &Timing, range: VrrRange) -> Option<Drr> {
    if !range.supports(t) || t.h_total == 0 || t.v_total == 0 {
        return None;
    }
    let nominal = nominal_uhz(t)?;
    let p100 = u64::from(t.pixel_clock_khz) * 10;
    // calc_max_hardware_v_total with vtotal_limited_by_fp2.
    let max_hw = u64::from(MAX_V_TOTAL.checked_sub(t.v_front_porch.checked_add(1)?)?);
    let min_hw = p100
        .checked_mul(100_000_000)?
        .checked_div(u64::from(t.h_total).checked_mul(max_hw)?)?;
    let config_min = u64::from(range.min_hz) * 1_000_000;
    let config_max = u64::from(range.max_hz) * 1_000_000;
    let mut max = config_max.min(nominal);
    let mut min = min_hw.max(config_min);
    if min > max {
        min = max;
    }
    let rounded_nominal = (nominal + 50_000) / 100_000 * 100_000;
    if config_max == 2 * config_min && config_max == rounded_nominal {
        min = nominal / 2;
    }
    // in_out_vrr's refresh fields are unsigned int.
    let min = u64::from(u32::try_from(min).ok()?);
    max = u64::from(u32::try_from(max).ok()?);
    let range_hz = ((max + 500_000) / 1_000_000).checked_sub((min + 500_000) / 1_000_000)?;
    if range_hz < u64::from(MIN_REFRESH_RANGE_HZ) {
        return None;
    }
    let v_total_min = calc_v_total_from_refresh(t, max, 0, 0)?;
    let v_total_max = calc_v_total_from_refresh(t, min, 0, 0)?;
    if v_total_max > MAX_V_TOTAL || v_total_min > MAX_V_TOTAL || v_total_min > v_total_max {
        return None;
    }
    Some(Drr {
        v_total_min,
        v_total_max,
    })
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_freesync_tests.rs"]
mod tests;
