//! Fixed unjoined S1/S2 Gen12 cursor reservation. MIT Linux b90c984d:
//! skl_watermark.c::{skl_cursor_allocation,skl_crtc_allocate_plane_ddb,
//! tgl_compute_sagv_wm,skl_need_wm_copy_wa}, intel_crtc.c::intel_crtc_bw_*.
//! A cursor is excluded from QGV bandwidth/count; clocks and MBUS stay fixed.
//! Repartition only with every pipe/fetcher off. Runtime never steals DDB.
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_dsb::Timing,
    intel_gpu_gt::Gen12Platform,
    intel_gpu_modeset::Mode,
    intel_gpu_wm::{self as wm, PlaneWatermarks, WmLevel, WmParams},
};
use alloc::vec::Vec;
use narf_filesystem::FsError;

const TOTAL: u16 = 2048;
const WM_OFFSETS: [u64; 9] = [0, 4, 8, 12, 16, 20, 24, 28, 40];
fn read(io: &(impl MmioWindow + ?Sized), r: u64) -> Result<u32, FsError> {
    let value = io.read32(r);
    if value == u32::MAX {
        Err(FsError::NoDevice)
    } else {
        Ok(value)
    }
}
fn checked(io: &(impl MmioWindow + ?Sized), r: u64, value: u32) -> Result<(), FsError> {
    read(io, r)?;
    io.write32(r, value);
    if read(io, r)? == value {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}
fn idle(io: &(impl MmioWindow + ?Sized)) -> Result<(), FsError> {
    for pipe in 0..4 {
        if read(io, 0x70008 + pipe * 0x1000)? & 0xc0000000 != 0
            || read(io, 0x70080 + pipe * 0x1000)? & 0x27 != 0
        {
            return Err(FsError::Unsupported);
        }
        for plane in 0..7 {
            if read(io, 0x70180 + pipe * 0x1000 + plane * 0x100)? & (1 << 31) != 0 {
                return Err(FsError::Unsupported);
            }
        }
        for dsb in 0..3 {
            if read(io, 0x70b08 + pipe * 0x1000 + dsb * 0x100)? & 0x80000001 != 0 {
                return Err(FsError::Unsupported);
            }
        }
    }
    if read(io, 0x43208)? & (1 << 31) != 0 {
        return Err(FsError::Unsupported);
    }
    Ok(())
}
fn encode(level: WmLevel) -> u32 {
    // Disabled higher levels retain the preceding sane blocks/lines (Gen12
    // PSR-related copy-down WAs); encode_wm_level intentionally zeros them.
    (if level.enable { 1 << 31 } else { 0 })
        | (u32::from(level.lines) << 14)
        | u32::from(level.blocks)
}
fn sane_disabled(wm: &mut PlaneWatermarks) {
    for level in 1..6 {
        if !wm.levels[level].enable {
            wm.levels[level].blocks = wm.levels[level - 1].blocks;
            wm.levels[level].lines = wm.levels[level - 1].lines;
        }
    }
}
fn levels(wm: PlaneWatermarks) -> [WmLevel; 9] {
    [
        wm.levels[0],
        wm.levels[1],
        wm.levels[2],
        wm.levels[3],
        wm.levels[4],
        wm.levels[5],
        wm.sagv,
        wm.sagv_trans,
        wm.trans,
    ]
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Profile {
    pub(crate) latencies: [u16; 6],
    primary: PlaneWatermarks,
    cursor: PlaneWatermarks,
    cursor_start: u16,
    family: Gen12Platform,
    ipc: bool,
}
impl Profile {
    fn compute(
        io: &(impl MmioWindow + ?Sized),
        mode: &Mode,
        family: Gen12Platform,
    ) -> Result<Self, FsError> {
        if mode.pixel_clock_khz == 0
            || mode.h_active == 0
            || mode.v_active == 0
            || mode.h_active >= mode.h_total
            || mode.v_active >= mode.v_total
            || mode.h_total > 8192
            || mode.v_total > 8192
        {
            return Err(FsError::Unsupported);
        }
        if matches!(
            family,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
        ) && read(io, 0x4438c)? & (1 << 31) != 0
        {
            return Err(FsError::Unsupported);
        }
        for r in [0x45008, 0x44fe8] {
            if read(io, r)? & 0xc0000000 != 0xc0000000 {
                return Err(FsError::Unsupported);
            }
        }
        let cdclk = (read(io, 0x46000)? & 0x7ff) * 500 + 1000;
        if mode.pixel_clock_khz > cdclk * 2 {
            return Err(FsError::Unsupported);
        }
        read(io, crate::intel_gpu_pcode::PCODE_MAILBOX)?;
        let raw = crate::intel_gpu_pcode::read_mem_latencies(io).map_err(|_| {
            if io.read32(crate::intel_gpu_pcode::PCODE_MAILBOX) == u32::MAX {
                FsError::NoDevice
            } else {
                FsError::Busy
            }
        })?;
        let latencies = wm::adjust_latencies(&raw);
        let block_time = crate::intel_gpu_pcode::read_sagv_block_time_us(io).map_err(|_| {
            if io.read32(crate::intel_gpu_pcode::PCODE_MAILBOX) == u32::MAX {
                FsError::NoDevice
            } else {
                FsError::Busy
            }
        })?;
        // No invented no-SAGV claim: require a real bounded SAGV latency and
        // enough private DDB for it, even if firmware currently disallows SAGV.
        if !(1..=u32::from(u16::MAX)).contains(&block_time) {
            return Err(FsError::Unsupported);
        }
        let ipc = read(io, 0x45004)? & (1 << 3) != 0;
        let params = WmParams {
            pixel_rate_khz: mode.pixel_clock_khz,
            htotal: u32::from(mode.h_total),
            width_px: 64,
            cpp: 4,
        };
        let mut cursor = wm::compute_plane_watermarks(&params, &latencies, block_time);
        let cursor_size = cursor
            .levels
            .iter()
            .filter(|w| w.enable)
            .map(|w| w.min_ddb_alloc)
            .max()
            .unwrap_or(0)
            .max(32);
        let cursor_start = TOTAL.checked_sub(cursor_size).ok_or(FsError::Unsupported)?;
        let mut primary = wm::compute_plane_watermarks(
            &WmParams {
                width_px: u32::from(mode.h_active),
                ..params
            },
            &latencies,
            block_time,
        );
        wm::validate_watermarks(&mut cursor, cursor_size);
        wm::validate_watermarks(&mut primary, cursor_start);
        if !cursor.levels[0].enable
            || !primary.levels[0].enable
            || !cursor.sagv.enable
            || !primary.sagv.enable
        {
            return Err(FsError::Unsupported);
        }
        if !ipc {
            cursor.trans = WmLevel::default();
            cursor.sagv_trans = WmLevel::default();
            primary.trans = WmLevel::default();
            primary.sagv_trans = WmLevel::default();
        }
        sane_disabled(&mut cursor);
        sane_disabled(&mut primary);
        Ok(Self {
            latencies,
            primary,
            cursor,
            cursor_start,
            family,
            ipc,
        })
    }
    pub(crate) fn capture(
        io: &(impl MmioWindow + ?Sized),
        timing: Timing,
        family: Gen12Platform,
    ) -> Result<Self, FsError> {
        let profile = Self::compute(
            io,
            &Mode {
                pixel_clock_khz: timing.clock,
                h_active: timing.width,
                h_total: timing.htotal,
                v_active: timing.height,
                v_total: timing.vtotal,
                ..Mode::VESA_1024X768_60
            },
            family,
        )?;
        profile.check(io, family)?;
        profile.check_cursor(io, false)?;
        for r in [0x700a0, 0x70080, 0x70088, 0x70084, 0x700ac] {
            if read(io, r)? != 0 {
                return Err(FsError::Unsupported);
            }
        }
        Ok(profile)
    }
    pub(crate) fn check(
        &self,
        io: &(impl MmioWindow + ?Sized),
        family: Gen12Platform,
    ) -> Result<(), FsError> {
        if self.family != family || (read(io, 0x45004)? & (1 << 3) != 0) != self.ipc {
            return Err(FsError::NoDevice);
        }
        for (offset, level) in WM_OFFSETS.into_iter().zip(levels(self.primary)) {
            if read(io, 0x70240 + offset)? != encode(level) {
                return Err(FsError::NoDevice);
            }
        }
        if read(io, 0x7027c)? != wm::encode_plane_buf_cfg(0, self.cursor_start)
            || read(io, 0x7017c)? != wm::encode_plane_buf_cfg(self.cursor_start, TOTAL)
        {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
    pub(crate) fn check_cursor(
        self,
        io: &(impl MmioWindow + ?Sized),
        enabled: bool,
    ) -> Result<(), FsError> {
        for (r, expected) in self.cursor_registers(enabled) {
            if read(io, r)? != expected {
                return Err(FsError::NoDevice);
            }
        }
        Ok(())
    }
    pub(crate) fn cursor_registers(self, enabled: bool) -> Vec<(u64, u32)> {
        let mut registers = Vec::new();
        for (offset, level) in WM_OFFSETS.into_iter().zip(levels(self.cursor)) {
            registers.push((0x70140 + offset, if enabled { encode(level) } else { 0 }));
        }
        registers.push((0x7017c, wm::encode_plane_buf_cfg(self.cursor_start, TOTAL)));
        registers
    }
}

/// None is a strictly pre-write refusal: keep the existing primary profile.
/// Any failure after the first resource write aborts before plane/pipe enable.
pub(crate) fn setup(
    io: &(impl MmioWindow + ?Sized),
    mode: &Mode,
    family: Gen12Platform,
) -> Result<Option<Profile>, FsError> {
    match idle(io) {
        Ok(()) => {}
        Err(FsError::Unsupported) => return Ok(None),
        Err(error) => return Err(error),
    }
    let profile = match Profile::compute(io, mode, family) {
        Ok(profile) => profile,
        Err(FsError::Unsupported | FsError::Busy) => return Ok(None),
        Err(error) => return Err(error),
    };
    // intel_dpt_common.c: display13 uses a global disable, not MTL's
    // per-plane chicken. All pipes/fetchers are proven stopped above; retain
    // disabled DPT for the lifetime of this fixed no-DPT pipeline.
    if matches!(
        family,
        Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
    ) {
        let value = read(io, 0x42084)?;
        checked(io, 0x42084, value | (1 << 30))?;
    }
    for (offset, level) in WM_OFFSETS.into_iter().zip(levels(profile.primary)) {
        checked(io, 0x70240 + offset, encode(level))?;
    }
    checked(
        io,
        0x7027c,
        wm::encode_plane_buf_cfg(0, profile.cursor_start),
    )?;
    for (r, value) in profile.cursor_registers(false) {
        checked(io, r, value)?;
    }
    for r in [0x700a0, 0x70080, 0x70088, 0x70084] {
        checked(io, r, 0)?;
    }
    profile.check(io, family)?;
    Ok(Some(profile))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_gen12_cursor_resource_tests.rs"]
mod tests;
