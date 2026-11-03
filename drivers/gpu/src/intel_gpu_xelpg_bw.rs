//! Display-14 memory bandwidth and SAGV/QGV point selection.
//!
//! MIT Linux b90c984d:
//! - `intel_dram.c::xelpdp_get_dram_info` (`MTL_MEM_SS_INFO_GLOBAL`: DDR
//!   type, populated channels, enabled QGV points);
//! - `intel_bw.c::mtl_read_qgv_point_info` (`MTL_MEM_SS_INFO_QGV_POINT_LOW/
//!   HIGH`), `icl_get_qgv_points` (display >= 14 DRAM parameters),
//!   `tgl_get_bw_info` with `mtl_sa_info` (y-tile assumed), `icl_sagv_max_dclk`,
//!   `tgl_max_bw_index` and `mtl_find_qgv_points`; the QGV peak bandwidth in
//!   100 MB/s units is the PM demand `QCLK_GV_BW` (`U16_MAX` masks SAGV);
//! - `tgl_get_bw_info`: one QGV point means SAGV is not controlled, and
//!   `intel_sagv_init` then zeroes the SAGV block time.
//!
//! Configurations Linux cannot describe (unsupported DRAM type, fewer
//! than two QGV points, a zero row-cycle time) keep SAGV masked.

use crate::intel_gpu_aux::MmioWindow;
use narf_filesystem::FsError;

/// `MTL_MEM_SS_INFO_GLOBAL`.
pub(crate) const MEM_SS_INFO_GLOBAL: u64 = 0x45700;
/// `MTL_MEM_SS_INFO_QGV_POINT_OFFSET`.
pub(crate) const QGV_POINT_BASE: u64 = 0x45710;
/// `I915_NUM_QGV_POINTS`.
pub(crate) const MAX_POINTS: usize = 8;
/// `ARRAY_SIZE(display->bw.max)`.
pub(crate) const GROUPS: usize = 6;

// mtl_sa_info.
const DEBURST: i64 = 32;
const DEPROGBWLIMIT_GBPS: i64 = 38;
const DISPLAYRTIDS: i64 = 256;
const DERATING: i64 = 10;
/// `DEPROGBWPCLIMIT`.
const DEPROGBWPCLIMIT: i64 = 60;

/// One QGV point (`struct intel_qgv_point`), clocks in MHz.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct QgvPoint {
    pub(crate) dclk: u16,
    pub(crate) t_rp: u16,
    pub(crate) t_rcd: u16,
    pub(crate) t_rdpre: u16,
    pub(crate) t_ras: u16,
    pub(crate) t_rc: u16,
}

/// Memory-subsystem QGV description (`struct intel_qgv_info` plus the
/// DRAM channel count), only for a SAGV-controllable configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Qgv {
    pub(crate) t_bl: u8,
    pub(crate) max_numchannels: u8,
    pub(crate) channel_width: u8,
    pub(crate) deinterleave: u8,
    pub(crate) num_channels: u8,
    pub(crate) num_points: u8,
    pub(crate) points: [QgvPoint; MAX_POINTS],
}

impl Qgv {
    /// `None` when SAGV cannot be controlled or described.
    pub(crate) fn read(io: &(impl MmioWindow + ?Sized)) -> Result<Option<Self>, FsError> {
        let read = |r: u64| {
            let v = io.read32(r);
            if v == u32::MAX || !io.display_access_ok() {
                Err(FsError::NoDevice)
            } else {
                Ok(v)
            }
        };
        let global = read(MEM_SS_INFO_GLOBAL)?;
        // icl_get_qgv_points, display >= 14.
        let (t_bl, max_numchannels, channel_width, deinterleave) = match global & 0xf {
            0 => (4, 2, 64, 2),  // DDR4
            1 => (8, 4, 32, 2),  // DDR5
            2 => (16, 8, 16, 4), // LPDDR5
            3 => (16, 8, 16, 4), // LPDDR4
            _ => return Ok(None),
        };
        let num_points = ((global >> 8) & 0xf) as u8;
        if num_points < 2 || usize::from(num_points) > MAX_POINTS {
            return Ok(None);
        }
        let mut points = [QgvPoint::default(); MAX_POINTS];
        for (i, p) in points.iter_mut().take(usize::from(num_points)).enumerate() {
            let low = read(QGV_POINT_BASE + i as u64 * 8)?;
            let high = read(QGV_POINT_BASE + i as u64 * 8 + 4)?;
            // DIV_ROUND_CLOSEST(16667 * dclk, 1000).
            let dclk = ((16667 * (low & 0xffff) + 500) / 1000) as u16;
            let t_rp = ((low >> 16) & 0xff) as u16;
            let t_ras = ((high >> 8) & 0x1ff) as u16;
            *p = QgvPoint {
                dclk,
                t_rp,
                t_rcd: (low >> 24) as u16,
                t_rdpre: (high & 0xff) as u16,
                t_ras,
                t_rc: t_rp + t_ras,
            };
        }
        Ok(Some(Self {
            t_bl,
            max_numchannels,
            channel_width,
            deinterleave,
            num_channels: ((global >> 4) & 0xf) as u8,
            num_points,
            points,
        }))
    }
}

/// `struct intel_bw_info` for one plane-count group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Group {
    pub(crate) num_planes: u8,
    pub(crate) deratedbw: [u32; MAX_POINTS],
    pub(crate) peakbw: [u32; MAX_POINTS],
}

/// `tgl_get_bw_info(.., &mtl_sa_info)`; `None` for a zero row-cycle time.
pub(crate) fn bw_info(q: &Qgv) -> Option<[Group; GROUPS]> {
    let mut num_channels = i64::from(q.num_channels.max(1));
    let mut deinterleave = i64::from(q.deinterleave);
    let max_channels = i64::from(q.max_numchannels);
    if num_channels < max_channels {
        deinterleave = ((deinterleave + 1) / 2).max(1);
    }
    num_channels = num_channels.min(max_channels);
    let points = &q.points[..usize::from(q.num_points)];
    let dclk_max = i64::from(points.iter().map(|p| p.dclk).max().unwrap_or(0));
    let width = i64::from(q.channel_width);
    let peakbw = num_channels * ((width + 7) / 8) * dclk_max;
    let maxdebw = (DEPROGBWLIMIT_GBPS * 1000).min(peakbw * DEPROGBWPCLIMIT / 100);
    let ipqdepth = 16.min(DISPLAYRTIDS / num_channels);
    let clperchgroup = 4 * ((8 + num_channels - 1) / num_channels) * deinterleave;
    let mut groups = [Group::default(); GROUPS];
    for i in 0..GROUPS {
        let clpchgroup = (DEBURST * deinterleave / num_channels) << i;
        if clpchgroup == 0 {
            return None;
        }
        if i + 1 < GROUPS {
            groups[i + 1].num_planes = if clpchgroup < clperchgroup {
                ((ipqdepth - clpchgroup) / clpchgroup + 1) as u8
            } else {
                0
            };
        }
        for (j, p) in points.iter().enumerate() {
            let ct = i64::from(p.t_rc).max(
                i64::from(p.t_rp)
                    + i64::from(p.t_rcd)
                    + (clpchgroup - 1) * i64::from(q.t_bl)
                    + i64::from(p.t_rdpre),
            );
            if ct <= 0 {
                return None;
            }
            let dclk = i64::from(p.dclk);
            let bw = (dclk * clpchgroup * 32 * num_channels + ct - 1) / ct;
            groups[i].deratedbw[j] = maxdebw.min(bw * (100 - DERATING) / 100) as u32;
            groups[i].peakbw[j] = ((dclk * num_channels * width + 4) / 8) as u32;
        }
    }
    Some(groups)
}

/// `tgl_max_bw_index`; `None` stands for `UINT_MAX`.
pub(crate) fn max_bw_index(
    groups: &[Group; GROUPS],
    num_points: u8,
    num_planes: u32,
    point: usize,
) -> Option<usize> {
    let num_planes = num_planes.max(1);
    for i in (0..GROUPS).rev() {
        if point >= usize::from(num_points) {
            return None;
        }
        if num_planes <= u32::from(groups[i].num_planes) {
            return Some(i);
        }
    }
    Some(0)
}

/// `mtl_find_qgv_points` with SAGV allowed: the QGV peak bandwidth in
/// 100 MB/s units of the point with the least derated headroom that still
/// carries `data_rate_mbps`; `None` when no point does.
pub(crate) fn qgv_peak_bw(q: &Qgv, data_rate_mbps: u32, num_planes: u32) -> Option<u16> {
    let groups = bw_info(q)?;
    let mut best = u32::MAX;
    let mut peak = 0u32;
    for point in 0..usize::from(q.num_points) {
        let Some(idx) = max_bw_index(&groups, q.num_points, num_planes, point) else {
            continue;
        };
        let max = groups[idx].deratedbw[point];
        if max < data_rate_mbps {
            continue;
        }
        if max - data_rate_mbps < best {
            best = max - data_rate_mbps;
            peak = groups[idx].peakbw[point];
        }
    }
    if peak == 0 {
        return None;
    }
    // DIV_ROUND_CLOSEST(qgv_peak_bw, 100), clamped by the PM demand field.
    Some(((peak + 50) / 100).min(u32::from(u16::MAX) - 1) as u16)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_bw_tests.rs"]
mod tests;
