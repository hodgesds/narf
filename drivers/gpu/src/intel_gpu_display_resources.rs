//! Fixed display14.00 Pipe-A resource ownership. MIT Linux b90c984d:
//! intel_bw.c::mtl_find_qgv_points (0xffff disables SAGV), intel_pmdemand.c,
//! intel_display_power.c::gen12_dbuf_slices_config, skl_watermark.c
//! (adlp_allowed_dbufs, pipe_mbus_dbox_ctl, cursor allocation), intel_cdclk.c.
//! All repartitioning occurs with every pipe/fetcher verified off. The owned
//! console keeps the fixed reservation/no-SAGV policy even with cursor hidden.
use crate::{intel_gpu_aux::MmioWindow, intel_gpu_modeset::Mode, intel_gpu_wm::*};
use narf_filesystem::FsError;

const REQUEST0: u64 = 0x45230;
const REQUEST1: u64 = 0x45234;
const INFLIGHT: u64 = 0x46440;
const ENABLE: u32 = 1 << 31;
const DBUFS: [u64; 4] = [0x45008, 0x44fe8, 0x44300, 0x44304];
const JOIN: u32 = (1 << 31) | (1 << 30) | (7 << 26); // joining while pipe is off
const DBOX: u32 = (16 << 20) | (1 << 17) | (1 << 16) | (3 << 14) | (10 << 8) | (2 << 5) | 12;
const TOTAL: u16 = 4096;

fn read(io: &(impl MmioWindow + ?Sized), r: u64) -> Result<u32, FsError> {
    let v = io.read32(r);
    if v == u32::MAX {
        Err(FsError::NoDevice)
    } else {
        Ok(v)
    }
}
fn checked(io: &(impl MmioWindow + ?Sized), r: u64, v: u32) -> Result<(), FsError> {
    read(io, r)?;
    io.write32(r, v);
    if read(io, r)? == v {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}
fn wait(io: &(impl MmioWindow + ?Sized), r: u64, mask: u32, want: u32) -> Result<(), FsError> {
    let mut error = None;
    let done = narf_scheduler::responsive_spin_until(
        || match read(io, r) {
            Ok(value) => value & mask == want,
            Err(failure) => {
                error = Some(failure);
                true
            }
        },
        narf_time::Deadline::after_ms(10),
    );
    if let Some(error) = error {
        Err(error)
    } else if done {
        Ok(())
    } else {
        Err(FsError::TimedOut)
    }
}
fn idle(io: &(impl MmioWindow + ?Sized)) -> Result<(), FsError> {
    for pipe in 0..4 {
        if read(io, 0x70008 + pipe * 0x1000)? & 0xc0000000 != 0
            || read(io, 0x70080 + pipe * 0x1000)? & 0x27 != 0
        {
            return Err(FsError::Unsupported);
        }
        for plane in 0..5 {
            if read(io, 0x70180 + pipe * 0x1000 + plane * 0x100)? & ENABLE != 0 {
                return Err(FsError::Unsupported);
            }
        }
        for dsb in 0..3 {
            if read(io, 0x70b08 + pipe * 0x1000 + dsb * 0x100)? & (ENABLE | 1) != 0 {
                return Err(FsError::Unsupported);
            }
        }
    }
    // The fixed owner cannot reset/allocate behind FBC or a foreign cursor.
    for r in [0x43208, 0x43248] {
        if read(io, r)? & ENABLE != 0 {
            return Err(FsError::Unsupported);
        }
    }
    Ok(())
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Profile {
    pub(crate) primary: PlaneWatermarks,
    pub(crate) cursor: PlaneWatermarks,
    pub(crate) cursor_start: u16,
}
impl Profile {
    fn compute(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<Self, FsError> {
        if mode.pixel_clock_khz == 0
            || mode.pixel_clock_khz > 1_305_600
            || mode.h_active == 0
            || mode.h_active >= mode.h_total
        {
            return Err(FsError::Unsupported);
        }
        let mut lat = [0u16; 6];
        for (i, r) in [0x45780, 0x45784, 0x45788].into_iter().enumerate() {
            let v = read(io, r)?;
            lat[i * 2] = (v & 0x1fff) as u16;
            lat[i * 2 + 1] = ((v >> 16) & 0x1fff) as u16;
        }
        let stop = lat
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, v)| **v == 0)
            .map_or(6, |(i, _)| i);
        lat[stop..].fill(0);
        for i in 1..stop {
            lat[i] = lat[i].max(lat[i - 1]);
        }
        if lat[0] == 0 {
            lat[0] = 6;
            for v in &mut lat[1..stop] {
                *v += 6;
            }
        }
        let params = WmParams {
            pixel_rate_khz: mode.pixel_clock_khz,
            htotal: u32::from(mode.h_total),
            width_px: 64,
            cpp: 4,
        };
        let mut cursor = compute_plane_watermarks(&params, &lat, 0);
        // The common linear algorithm is identical for display14; its existing
        // 31-line ceiling is deliberately stricter than display14's255.
        let cursor_size = cursor
            .levels
            .iter()
            .filter(|w| w.enable)
            .map(|w| w.min_ddb_alloc)
            .max()
            .unwrap_or(0)
            .max(32);
        let cursor_start = TOTAL.checked_sub(cursor_size).ok_or(FsError::Unsupported)?;
        let mut primary = compute_plane_watermarks(
            &WmParams {
                width_px: u32::from(mode.h_active),
                ..params
            },
            &lat,
            0,
        );
        validate_watermarks(&mut cursor, cursor_size);
        validate_watermarks(&mut primary, cursor_start);
        if !primary.levels[0].enable
            || !cursor.levels[0].enable
            || cursor.levels.iter().any(|w| w.blocks > 0xfff)
        {
            return Err(FsError::Unsupported);
        }
        Ok(Self {
            primary,
            cursor,
            cursor_start,
        })
    }
    pub(crate) fn cursor_registers(self, enabled: bool) -> alloc::vec::Vec<(u64, u32)> {
        let mut regs = alloc::vec::Vec::new();
        for (i, wm) in self.cursor.levels.iter().enumerate() {
            regs.push((
                0x70140 + i as u64 * 4,
                if enabled { encode_wm_level(wm) } else { 0 },
            ));
        }
        regs.extend([
            (0x70158, 0),
            (0x7015c, 0),
            (
                0x70168,
                if enabled {
                    encode_wm_level(&self.cursor.trans)
                } else {
                    0
                },
            ),
            (0x7017c, encode_plane_buf_cfg(self.cursor_start, TOTAL)),
        ]);
        regs
    }
    /// Runtime cursor admission requires the exact source-owned global layout,
    /// powered slices and acknowledged no-SAGV request, not a generation flag.
    pub(crate) fn capture_timing(
        io: &(impl MmioWindow + ?Sized),
        timing: crate::intel_gpu_dsb::Timing,
    ) -> Result<Self, FsError> {
        let mode = Mode {
            pixel_clock_khz: timing.clock,
            h_active: timing.width,
            h_total: timing.htotal,
            v_active: timing.height,
            v_total: timing.vtotal,
            ..Mode::VESA_1024X768_60
        };
        Self::capture(io, &mode)
    }
    pub(crate) fn capture(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<Self, FsError> {
        let profile = Self::capture_layout(io, mode)?;
        let pll = read(io, 0x46070)?;
        let ctl = read(io, 0x46000)?;
        let squash = read(io, 0x46008)?;
        if pll & 0xc0000000 != 0xc0000000
            || ctl & (3 << 22) != 0
            || (squash & (1 << 31) != 0 && squash & (15 << 24) != 15 << 24)
        {
            return Err(FsError::Unsupported);
        }
        let actual = crate::intel_gpu_modeset_xelpg::cdclk_current_khz(io);
        if !(1..=652800).contains(&actual) || mode.pixel_clock_khz > actual * 2 {
            return Err(FsError::Unsupported);
        }
        let voltage = if actual <= 312000 {
            0
        } else if actual <= 480000 {
            1
        } else if actual <= 556800 {
            2
        } else {
            3
        };
        let req0 = read(io, REQUEST0)?;
        let req1 = read(io, REQUEST1)?;
        if ((req0 >> 12) & 7) < voltage || ((req1 >> 20) & 2047) < actual.div_ceil(1000) {
            return Err(FsError::Unsupported);
        }
        Ok(profile)
    }
    fn capture_layout(io: &(impl MmioWindow + ?Sized), mode: &Mode) -> Result<Self, FsError> {
        let gmd = read(io, 0x510a0)?;
        if gmd >> 22 != 14 || (gmd >> 14) & 255 != 0 {
            return Err(FsError::Unsupported);
        }
        // The joined allocation and one-active-pipe PM demand belong to
        // Pipe A alone. An enabled blank foreign pipe still consumes global
        // display resources, even when none of its fetchers is enabled.
        for pipe in 1..4 {
            if read(io, 0x70008 + pipe * 0x1000)? & 0xc0000000 != 0 {
                return Err(FsError::Unsupported);
            }
        }
        let profile = Self::compute(io, mode)?;
        let req0 = read(io, REQUEST0)?;
        let req1 = read(io, REQUEST1)?;
        if req0 >> 16 != 0xffff
            || (req0 >> 6) & 3 < 1
            || (req0 >> 4) & 3 != 3
            || req0 & 7 < 1
            || (req1 >> 8) & 2047 < 810
            || (req1 >> 4) & 7 != 7
            || req1 & 7 < 2
            || read(io, 0x44468)? & (1 << 27) != 0
            || read(io, REQUEST1)? & ENABLE != 0
            || read(io, INFLIGHT)? & (1 << 26) != 0
            || read(io, 0x4438c)? & 0xdc000000 != JOIN
            || read(io, 0x7003c)? != DBOX
            || read(io, 0x45004)? & (1 << 3) == 0
            || read(io, 0x7027c)? != encode_plane_buf_cfg(0, profile.cursor_start)
            || read(io, 0x7017c)? != encode_plane_buf_cfg(profile.cursor_start, TOTAL)
        {
            return Err(FsError::Unsupported);
        }
        for r in DBUFS {
            if read(io, r)? & 0xc0ff0000 != 0xc0430000 {
                return Err(FsError::Unsupported);
            }
        }
        for (i, wm) in profile.primary.levels.iter().enumerate() {
            if read(io, 0x70240 + i as u64 * 4)? != encode_wm_level(wm) {
                return Err(FsError::Unsupported);
            }
        }
        if read(io, 0x70258)? != 0
            || read(io, 0x7025c)? != 0
            || read(io, 0x70268)? != encode_wm_level(&profile.primary.trans)
        {
            return Err(FsError::Unsupported);
        }
        Ok(profile)
    }
}
/// None is a strict, read-only refusal before writes: older boot modes may
/// continue with inherited resources, but cannot acquire the cursor profile.
/// Once the request or any resource is exposed, failure leaves the pipe off;
/// no caller may enable it or publish a cursor on that partial baseline.
pub(crate) fn initialize(
    io: &(impl MmioWindow + ?Sized),
    mode: &Mode,
    cdclk: u32,
) -> Result<Option<Profile>, FsError> {
    let gmd = read(io, 0x510a0)?;
    if gmd >> 22 != 14 || (gmd >> 14) & 255 != 0 {
        return Ok(None);
    }
    match idle(io) {
        Ok(()) => {}
        Err(FsError::Unsupported) => return Ok(None),
        Err(e) => return Err(e),
    }
    let profile = match Profile::compute(io, mode) {
        Ok(v) => v,
        Err(FsError::Unsupported) => return Ok(None),
        Err(e) => return Err(e),
    };
    if !(1..=652800).contains(&cdclk) || mode.pixel_clock_khz > cdclk * 2 {
        return Ok(None);
    }
    let irq_enable = read(io, 0x4446c)?;
    let irq_mask = io.read32(0x44464); // all masked is a valid value
    if irq_enable & !irq_mask & ((1 << 3) | (1 << 27)) != 0 || read(io, 0x44468)? & (1 << 27) != 0 {
        return Ok(None);
    }
    wait(io, REQUEST1, ENABLE, 0)?;
    wait(io, INFLIGHT, 1 << 26, 0)?;
    // Wa_14016740474: display14.00 A0..<C0. STEP_* enumerates four
    // substeps per letter; GMD display stepping is the zero-based offset.
    if gmd & 63 < 8 {
        let v = read(io, 0x46438)?;
        checked(io, 0x46438, v | (1 << 19))?;
    }
    let voltage = if cdclk <= 312000 {
        0
    } else if cdclk <= 480000 {
        1
    } else if cdclk <= 556800 {
        2
    } else {
        3
    };
    let old0 = read(io, REQUEST0)?;
    let old1 = read(io, REQUEST1)?;
    let maxfield =
        |old: u32, value: u32, shift: u32, mask: u32| (((old & mask) >> shift).max(value)) << shift;
    let reg0 = (old0 & !(0xffff0000 | 0x7000 | 0xf00 | 0xc0 | 0x30 | 7))
        | 0xffff0000
        | maxfield(old0, voltage, 12, 0x7000)
        | maxfield(old0, 0, 8, 0xf00)
        | maxfield(old0, 1, 6, 0xc0)
        | maxfield(old0, 3, 4, 0x30)
        | maxfield(old0, 1, 0, 7);
    let reg1 = (old1 & !(0x7ff00000 | 0x7ff00 | 0x70 | 7))
        | maxfield(old1, cdclk.div_ceil(1000), 20, 0x7ff00000)
        | maxfield(old1, 810, 8, 0x7ff00)
        | maxfield(old1, 7, 4, 0x70)
        | maxfield(old1, 2, 0, 7);
    checked(io, REQUEST0, reg0)?;
    checked(io, REQUEST1, reg1)?;
    io.write32(REQUEST1, reg1 | ENABLE);
    wait(io, REQUEST1, ENABLE, 0)?;
    wait(io, INFLIGHT, 1 << 26, 0)?;
    if read(io, REQUEST0)? != reg0
        || read(io, REQUEST1)? != reg1
        || read(io, 0x44468)? & (1 << 27) != 0
    {
        return Err(FsError::NoDevice);
    }
    for r in DBUFS {
        let old = read(io, r)?;
        let value = (old & !0x00ff0000) | ENABLE | (8 << 19) | (3 << 16);
        io.write32(r, value);
        wait(io, r, 1 << 30, 1 << 30)?;
        if read(io, r)? & 0xc0ff0000 != 0xc0430000 {
            return Err(FsError::NoDevice);
        }
    }
    let mbus = read(io, 0x4438c)?;
    checked(io, 0x4438c, (mbus & !0xdc000000) | JOIN)?;
    checked(io, 0x7003c, DBOX)?;
    // skl_watermark_ipc_update: transition watermarks require IPC. Own its
    // enable while the pipes are off instead of inheriting firmware policy.
    let arb = read(io, 0x45004)?;
    checked(io, 0x45004, arb | (1 << 3))?;
    // Every disabled plane's DDB/WM reset values must be zero; no firmware
    // allocation is allowed to alias our fixed primary/cursor partition.
    for pipe in 0..4 {
        for plane in 0..5 {
            let base = 0x70240 + pipe * 0x1000 + plane * 0x100;
            for off in [0, 4, 8, 12, 16, 20, 24, 28, 40, 60] {
                checked(io, base + off, 0)?;
            }
        }
    }
    for (i, wm) in profile.primary.levels.iter().enumerate() {
        checked(io, 0x70240 + i as u64 * 4, encode_wm_level(wm))?;
    }
    checked(io, 0x70268, encode_wm_level(&profile.primary.trans))?;
    checked(io, 0x7027c, encode_plane_buf_cfg(0, profile.cursor_start))?;
    for pipe in 0..4 {
        for off in [
            0x140, 0x144, 0x148, 0x14c, 0x150, 0x154, 0x158, 0x15c, 0x168, 0x17c,
        ] {
            checked(io, 0x70000 + pipe * 0x1000 + off, 0)?;
        }
    }
    for (r, v) in profile.cursor_registers(false) {
        checked(io, r, v)?;
    }
    for r in [0x70080, 0x70088, 0x70084] {
        checked(io, r, 0)?;
    }
    Profile::capture_layout(io, mode)?;
    Ok(Some(profile))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_display_resources_tests.rs"]
mod tests;
