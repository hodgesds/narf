//! Native DCN401 hardware cursor on a live single-pipe scanout. Linux:
//! dcn10_set_cursor_attribute (hubp32_cursor_set_attributes,
//! dpp401_set_cursor_attributes, dpp401_set_cursor_sdr_white_level),
//! dcn401_set_cursor_position (hubp401_cursor_set_position,
//! dpp401_set_cursor_position), all inside dcn10_cursor_lock's
//! mpc1_cursor_lock (CUR_VUPDATE_LOCK_SET of the pipe's OPP). Linux caps the
//! DCN401 cursor at 64x64 (dcn401_resource max_cursor_size), which also keeps
//! it out of MALL; DML21 already budgets a 256-wide ARGB cursor per plane.
use super::*;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

pub const CURSOR_MAX: u32 = 64;
const CONTROL: u64 = 0x679; // CURSOR0_n, HUBP stride
const ADDRESS: u64 = 0x67a;
const ADDRESS_HIGH: u64 = 0x67b;
const SIZE: u64 = 0x67c;
const POSITION: u64 = 0x67d;
const HOT_SPOT: u64 = 0x67e;
const DST_OFFSET: u64 = 0x680;
const SETTINGS: u64 = 0x653; // HUBPREQ_CURSOR_SETTINGS
const ENABLE: u32 = 1;
const REQ_MODE: u32 = 4;
/// CURSOR_MODE, 2X_MAGNIFY, PITCH and LINES_PER_CHUNK.
const CONTROL_FIELDS: u32 = 0x1f03_0710;
const PRE_MULTIPLIED: u32 = 2;
const CM_CONTROL: u64 = 0xcf1; // CM_CUR0, DPP stride 0x16b
const CM_SCALE_G_Y: u64 = 0xcf4;
const CM_SCALE_RB: u64 = 0xcf5;
const CM_MATRIX: u64 = 0xcf6;
/// CUR0_ENABLE, EXPANSION_MODE, ROM_EN and MODE.
const CM_FIELDS: u32 = 0x7b;
const FP16_ONE: u32 = 0x3c00;
const LOCK_SET: u64 = 0x2c5; // MPC block, stride 5 per OPP

/// The owned cursor image and where it is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorApplied {
    pub pipe: u8,
    pub address: u64,
    pub width: u32,
    pub height: u32,
    /// Screen position of the image's top-left pixel, as DRM's crtc_x/y.
    pub x: i32,
    pub y: i32,
    /// Programmed enable: false while the image is entirely off screen.
    pub visible: bool,
}

/// What the position registers hold for a placement, following
/// dcn401_set_cursor_position in the 1:1, full-recout single-pipe case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Placement {
    pub(super) visible: bool,
    pub(super) x: u32,
    pub(super) y: u32,
    pub(super) hot_x: u32,
    pub(super) hot_y: u32,
    pub(super) dst_x_offset: u32,
}
pub(super) fn placement(
    x: i32,
    y: i32,
    (width, height): (u32, u32),
    (active_w, active_h): (u32, u32),
    (refclk_khz, pixclk_khz): (u32, u32),
) -> Placement {
    let hidden = Placement {
        visible: false,
        x: 0,
        y: 0,
        hot_x: 0,
        hot_y: 0,
        dst_x_offset: 0,
    };
    let (w, h) = (width as i64, height as i64);
    let (x, y) = (i64::from(x), i64::from(y));
    // A negative origin moves into the hotspot (amdgpu_dm/dcn401); the
    // remaining on-screen part starts at 0.
    let (px, hot_x) = if x < 0 { (0, -x) } else { (x, 0) };
    let (py, hot_y) = if y < 0 { (0, -y) } else { (y, 0) };
    let (rx, ry) = (px - hot_x, py - hot_y);
    if hot_x >= w || hot_y >= h || rx >= i64::from(active_w) || ry >= i64::from(active_h) {
        return hidden;
    }
    // CURSOR_DST_X_OFFSET is in DCHUB reference clocks.
    let dst = (rx.max(0) * i64::from(refclk_khz) / i64::from(pixclk_khz.max(1))) as u32;
    Placement {
        visible: true,
        x: px as u32,
        y: py as u32,
        hot_x: hot_x as u32,
        hot_y: hot_y as u32,
        dst_x_offset: dst.min(0x3fff),
    }
}
/// At most 64x64 (Linux's DCN401 cap), one pixel per position.
fn validate_image(width: u32, height: u32, pixels: &[u32]) -> Result<(), Error> {
    if !(1..=CURSOR_MAX).contains(&width)
        || !(1..=CURSOR_MAX).contains(&height)
        || pixels.len() != (width * height) as usize
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// CURSOR_LINES_PER_CHUNK for 32 bpp (hubp2_get_lines_per_chunk).
fn lines_per_chunk(width: u32) -> u32 {
    match width {
        0..=32 => 4,
        33..=64 => 3,
        65..=128 => 2,
        _ => 1,
    }
}

impl<I: Io> Engine<I> {
    fn cm(&self, pipe: u8, reg: u64) -> u64 {
        self.layout.base + (reg + u64::from(pipe) * 0x16b) * 4
    }
    fn cursor_lock_at(&self, pipe: u8) -> u64 {
        self.layout.mpc_base + (LOCK_SET + u64::from(pipe) * 5) * 4
    }
    /// Cursor registers latch together at the VUPDATE after the lock drops.
    fn cursor_locked(
        &mut self,
        pipe: u8,
        writes: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let at = self.cursor_lock_at(pipe);
        self.update(at, 1, 1)?;
        let result = writes(self);
        // Always release: a held cursor lock would freeze cursor latching.
        self.update(at, 1, 0)?;
        result
    }
    pub(super) fn cursor_attributes(&mut self, a: CursorApplied) -> [(u64, u32, u32); 9] {
        let l = self.layout;
        let p = a.pipe;
        [
            (l.hubp(p, ADDRESS_HIGH), 0xffff, (a.address >> 32) as u32),
            (l.hubp(p, ADDRESS), u32::MAX, a.address as u32),
            (l.hubp(p, SIZE), 0x01ff_01ff, a.width << 16 | a.height),
            // Pitch 64 pixels (field 0), no magnification, early requests.
            (
                l.hubp(p, CONTROL),
                CONTROL_FIELDS | REQ_MODE,
                lines_per_chunk(a.width) << 24 | PRE_MULTIPLIED << 8 | REQ_MODE,
            ),
            (l.hubp(p, SETTINGS), u32::MAX, 0x300), // full write, as Linux
            (
                self.cm(p, CM_CONTROL),
                CM_FIELDS & !ENABLE,
                PRE_MULTIPLIED << 4,
            ),
            (self.cm(p, CM_SCALE_G_Y), u32::MAX, FP16_ONE),
            (self.cm(p, CM_SCALE_RB), u32::MAX, FP16_ONE),
            (self.cm(p, CM_MATRIX), 3, 0),
        ]
    }
    fn cursor_position(&mut self, pipe: u8, at: Placement) -> [(u64, u32, u32); 5] {
        let l = self.layout;
        let en = u32::from(at.visible);
        [
            (l.hubp(pipe, POSITION), 0x3fff_ffff, at.x << 15 | at.y),
            (
                l.hubp(pipe, HOT_SPOT),
                0x00ff_00ff,
                at.hot_x << 16 | at.hot_y,
            ),
            (l.hubp(pipe, DST_OFFSET), 0x3fff, at.dst_x_offset),
            (l.hubp(pipe, CONTROL), ENABLE, en),
            (self.cm(pipe, CM_CONTROL), ENABLE, en),
        ]
    }
    pub(super) fn program_cursor(&mut self, a: CursorApplied, at: Placement) -> Result<(), Error> {
        let attributes = self.cursor_attributes(a);
        let position = self.cursor_position(a.pipe, at);
        self.cursor_locked(a.pipe, |e| {
            for (at, mask, value) in attributes.into_iter().chain(position) {
                e.update(at, mask, value)?;
            }
            Ok(())
        })
    }
    pub(super) fn verify_cursor(&mut self, a: CursorApplied, at: Placement) -> Result<(), Error> {
        let attributes = self.cursor_attributes(a);
        let position = self.cursor_position(a.pipe, at);
        for (at, mask, value) in attributes.into_iter().chain(position) {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        if self.read(self.cursor_lock_at(a.pipe))? & 1 != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    /// Disable both cursor enables; used before the plane stops.
    pub(super) fn hide_cursor(&mut self, pipe: u8) -> Result<(), Error> {
        let (hubp, cm) = (self.layout.hubp(pipe, CONTROL), self.cm(pipe, CM_CONTROL));
        self.cursor_locked(pipe, |e| {
            e.update(hubp, ENABLE, 0)?;
            e.update(cm, ENABLE, 0)
        })
    }
}

impl Surfaces {
    /// Upload a premultiplied ARGB8888 image (row-major, `width` x `height`,
    /// at most 64x64) into the pipe's cursor buffer, allocated on first use,
    /// and show it at (`x`, `y`). Requires a live scanout on the pipe.
    pub(in crate::amdgpu_dcn401_otg) fn set_cursor<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pool: &Pool,
        config: DisplayContext,
        pipe: u8,
        image: (u32, u32, &[u32]),
        (x, y): (i32, i32),
    ) -> Result<CursorApplied, Error> {
        let (width, height, pixels) = image;
        validate_image(width, height, pixels)?;
        let running = e.status.scanout.ok_or(Error::Invalid)?;
        if e.status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
            return Err(Error::Busy);
        }
        let slot = usize::from(pipe);
        let surface = self
            .0
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(Error::Invalid)?;
        if surface.cursor.is_none() {
            let mut memory = pool
                .reserve(u64::from(CURSOR_MAX * CURSOR_MAX * 4))
                .map_err(|_| Error::Allocation)?;
            if memory.address() < config.fb_base
                || memory
                    .address()
                    .checked_add(memory.size() - 1)
                    .is_none_or(|last| last > config.fb_top || last >= 1 << 48)
            {
                return Err(Error::Invalid);
            }
            memory.publish();
            surface.cursor = Some(memory);
        }
        let memory = surface.cursor.as_ref().ok_or(Error::Invalid)?;
        let map = memory.mapping();
        let address = memory.address();
        // Pitch is the full 64-pixel row; padding stays transparent black.
        e.access(|_| {
            for row in 0..CURSOR_MAX {
                for col in 0..CURSOR_MAX {
                    let pixel = if row < height && col < width {
                        pixels[(row * width + col) as usize]
                    } else {
                        0
                    };
                    // SAFETY: live authority; offset within the owned 16 KiB buffer.
                    unsafe { map.write32(u64::from(row * CURSOR_MAX + col) * 4, pixel) };
                }
            }
            Ok(())
        })?;
        e.flush_surface_writes()?;
        let applied = CursorApplied {
            pipe,
            address,
            width,
            height,
            x,
            y,
            visible: false,
        };
        self.place_cursor(e, applied)
    }
    /// Move the owned cursor; hidden when entirely off screen.
    pub(in crate::amdgpu_dcn401_otg) fn move_cursor<I: Io>(
        &self,
        e: &mut Engine<I>,
        pipe: u8,
        (x, y): (i32, i32),
    ) -> Result<CursorApplied, Error> {
        let current = e.status.cursor.ok_or(Error::Invalid)?;
        if current.pipe != pipe || e.status.state != State::ScanoutRunning(pipe) {
            return Err(Error::Busy);
        }
        self.place_cursor(e, CursorApplied { x, y, ..current })
    }
    fn place_cursor<I: Io>(
        &self,
        e: &mut Engine<I>,
        a: CursorApplied,
    ) -> Result<CursorApplied, Error> {
        let deadlines = e.status.deadlines.ok_or(Error::Invalid)?;
        let timing = deadlines.plan.mode.timing;
        let at = placement(
            a.x,
            a.y,
            (a.width, a.height),
            (timing.h_active, timing.v_active),
            (deadlines.plan.soc.dchub_refclk_khz, timing.pixel_clock_khz),
        );
        let a = CursorApplied {
            visible: at.visible,
            ..a
        };
        e.status.state = State::Cursor(a.pipe);
        e.status.cursor = None;
        match e
            .program_cursor(a, at)
            .and_then(|()| e.verify_cursor(a, at))
        {
            Ok(()) => {
                e.status.cursor = Some(a);
                e.status.state = State::ScanoutRunning(a.pipe);
                Ok(a)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}

impl Otg {
    /// Show a premultiplied ARGB8888 cursor (at most 64x64) on a live pipe.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers; the cursor
    /// buffer is retained by the pipe for the owner's lifetime.
    pub unsafe fn set_cursor(
        &mut self,
        pool: &Pool,
        gmc: &mut Gmc,
        pipe: u8,
        image: (u32, u32, &[u32]),
        position: (i32, i32),
    ) -> Result<CursorApplied, Error> {
        let config = gmc.display_context(self.0.io.0).map_err(Error::Memory)?;
        self.1
            .set_cursor(&mut self.0, pool, config, pipe, image, position)
    }
    /// Move the live cursor.
    /// # Safety
    /// As for `set_cursor`.
    pub unsafe fn move_cursor(
        &mut self,
        pipe: u8,
        position: (i32, i32),
    ) -> Result<CursorApplied, Error> {
        self.1.move_cursor(&mut self.0, pipe, position)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_cursor_tests.rs"]
mod tests;
