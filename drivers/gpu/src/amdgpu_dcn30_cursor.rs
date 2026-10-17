//! DCN3.0 hardware cursor of one live pipe. Linux: `dcn10_set_cursor_attribute`
//! (`hubp2_cursor_set_attributes`, `dpp3_set_cursor_attributes`) and
//! `dcn10_set_cursor_position` (`hubp2_cursor_set_position`,
//! `dpp1_set_cursor_position`), each inside `dcn10_cursor_lock`'s
//! `mpc1_cursor_lock` (CUR_VUPDATE_LOCK_SET of the pipe's OPP), with the
//! negative-origin hotspot of amdgpu_dm's `get_cursor_position`. DCN3.0's cap
//! is 256x256 (`dcn30_resource.c` max_cursor_size); the image is premultiplied
//! ARGB8888 at a fixed 256-pixel pitch, without degamma (CUR0_ROM_EN off).
//!
//! Offsets (`dcn_3_0_0_offset.h`): CURSOR0_n and HUBPREQn at DCN base index
//! 2 with stride 0xdc, CNVC_CURn (DPP) at base index 2 with stride 0x16b, and
//! CUR_VUPDATE_LOCK_SETn at base index 3 with stride 5.
use crate::{amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

pub const CURSOR_MAX: u32 = 256;
/// The image pitch in pixels, and CURSOR_PITCH's code for it.
pub const PITCH: u32 = 256;
const PITCH_256: u32 = 2;
pub(crate) const CURSOR_CONTROL: u64 = 0x0678;
pub(crate) const CURSOR_SURFACE_ADDRESS: u64 = 0x0679;
pub(crate) const CURSOR_SURFACE_ADDRESS_HIGH: u64 = 0x067a;
pub(crate) const CURSOR_SIZE: u64 = 0x067b;
pub(crate) const CURSOR_POSITION: u64 = 0x067c;
pub(crate) const CURSOR_HOT_SPOT: u64 = 0x067d;
pub(crate) const CURSOR_DST_OFFSET: u64 = 0x067f;
pub(crate) const CURSOR_SETTINGS: u64 = 0x065c;
pub(crate) const HUBP_STRIDE: u64 = 0xdc;
pub(crate) const CUR0_CONTROL: u64 = 0x0cf1;
pub(crate) const DPP_STRIDE: u64 = 0x16b;
pub(crate) const CUR_VUPDATE_LOCK_SET: u64 = 0x0513;
pub(crate) const LOCK_STRIDE: u64 = 5;

const ENABLE: u32 = 1;
/// CURSOR_MODE, CURSOR_2X_MAGNIFY, CURSOR_PITCH and CURSOR_LINES_PER_CHUNK.
const CONTROL_FIELDS: u32 = 0x0000_0700 | 0x0000_0010 | 0x0003_0000 | 0x1f00_0000;
/// CURSOR_MODE_COLOR_PRE_MULTIPLIED_ALPHA (dc_cursor_color_format).
const PRE_MULTIPLIED: u32 = 2;
const SIZE_MASK: u32 = 0x01ff_01ff;
const POSITION_MASK: u32 = 0x3fff;
const HOT_SPOT_MASK: u32 = 0xff;
const DST_X_OFFSET_MASK: u32 = 0x1fff;
/// CURSOR0_CHUNK_HDL_ADJUST = 3, CURSOR0_DST_Y_OFFSET = 0.
const SETTINGS: u32 = 3 << 8;
/// CUR0_ENABLE, CUR0_EXPANSION_MODE, CUR0_ROM_EN and CUR0_MODE.
const CUR0_FIELDS: u32 = 0x1 | 0x2 | 0x8 | 0x70;

/// CURSOR_LINES_PER_CHUNK for a 32-bpp colour cursor
/// (`hubp2_get_lines_per_chunk`, `enum cursor_lines_per_chunk`).
pub(crate) fn lines_per_chunk(width: u32) -> u32 {
    match width {
        0..=32 => 4,
        33..=64 => 3,
        65..=128 => 2,
        _ => 1,
    }
}

/// What the position registers hold for a placement in the 1:1, unrotated,
/// full-viewport single-pipe case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub visible: bool,
    pub x: u32,
    pub y: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub dst_x_offset: u32,
}
/// amdgpu_dm `get_cursor_position` (a negative origin moves into the hotspot,
/// at most `CURSOR_MAX - 1`, and an origin at or beyond -max disables) then
/// the visibility and `CURSOR_DST_X_OFFSET` of `hubp2_cursor_set_position`
/// (in DCHUB reference clocks: `src_x_offset * refclk / pixclk`).
pub fn placement(
    x: i32,
    y: i32,
    (width, height): (u32, u32),
    (view_w, view_h): (u32, u32),
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
    let max = i64::from(CURSOR_MAX);
    let (x, y) = (i64::from(x), i64::from(y));
    if x <= -max || y <= -max || pixclk_khz == 0 {
        return hidden;
    }
    let (px, hot_x) = if x < 0 {
        (0, (-x).min(max - 1))
    } else {
        (x, 0)
    };
    let (py, hot_y) = if y < 0 {
        (0, (-y).min(max - 1))
    } else {
        (y, 0)
    };
    let (sx, sy) = (px - hot_x, py - hot_y);
    let (w, h) = (i64::from(width), i64::from(height));
    if sx >= i64::from(view_w) || sx + w <= 0 || sy >= i64::from(view_h) || sy + h <= 0 {
        return hidden;
    }
    if px > i64::from(POSITION_MASK) || py > i64::from(POSITION_MASK) {
        return hidden;
    }
    let dst = sx.max(0) * i64::from(refclk_khz) / i64::from(pixclk_khz);
    Placement {
        visible: true,
        x: px as u32,
        y: py as u32,
        hot_x: hot_x as u32,
        hot_y: hot_y as u32,
        dst_x_offset: (dst as u32).min(DST_X_OFFSET_MASK),
    }
}

pub(crate) trait Io: Send {
    /// Absolute byte offsets in the GPU's register BAR.
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: the constructor bounded both DCN banks this owner uses.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: as above; the pipe's owner serializes every writer.
        unsafe { self.0.write32(at, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

/// The programmed cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shown {
    pub address: u64,
    pub width: u32,
    pub height: u32,
    pub x: i32,
    pub y: i32,
    pub placement: Placement,
}

#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub(crate) io: I,
    pub(crate) authority: Cap<BusDeviceCap, Write>,
    /// DCN base index 2 and 3, as byte offsets.
    pub(crate) dcn2: u64,
    pub(crate) dcn3: u64,
    pub(crate) pipe: u8,
    pub(crate) shown: Option<Shown>,
}
impl<I: Io> Engine<I> {
    fn hubp(&self, reg: u64) -> u64 {
        self.dcn2 + (reg + u64::from(self.pipe) * HUBP_STRIDE) * 4
    }
    fn dpp(&self, reg: u64) -> u64 {
        self.dcn2 + (reg + u64::from(self.pipe) * DPP_STRIDE) * 4
    }
    fn lock_reg(&self) -> u64 {
        // The console pipe's MPCC tree feeds the OPP of the same index.
        self.dcn3 + (CUR_VUPDATE_LOCK_SET + u64::from(self.pipe) * LOCK_STRIDE) * 4
    }
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn update(&mut self, at: u64, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.access(|io| io.read(at))?;
        if old == u32::MAX {
            return Err(Error::DeviceGone);
        }
        self.access(|io| io.write(at, (old & !mask) | (value & mask)))
    }
    fn set(&mut self, at: u64, value: u32) -> Result<(), Error> {
        self.access(|io| io.write(at, value))
    }
    /// `mpc1_cursor_lock` around `writes`; the lock is always released so a
    /// failure cannot freeze cursor latching.
    fn locked(&mut self, writes: impl FnOnce(&mut Self) -> Result<(), Error>) -> Result<(), Error> {
        let lock = self.lock_reg();
        self.set(lock, 1)?;
        let result = writes(self);
        result.and(self.set(lock, 0))
    }
    /// `hubp2_cursor_set_attributes` + `dpp3_set_cursor_attributes`.
    fn attributes(&mut self, address: u64, width: u32, height: u32) -> Result<(), Error> {
        self.update(
            self.hubp(CURSOR_SURFACE_ADDRESS_HIGH),
            0xffff,
            (address >> 32) as u32,
        )?;
        self.set(self.hubp(CURSOR_SURFACE_ADDRESS), address as u32)?;
        self.update(self.hubp(CURSOR_SIZE), SIZE_MASK, width << 16 | height)?;
        self.update(
            self.hubp(CURSOR_CONTROL),
            CONTROL_FIELDS,
            lines_per_chunk(width) << 24 | PITCH_256 << 16 | PRE_MULTIPLIED << 8,
        )?;
        self.set(self.hubp(CURSOR_SETTINGS), SETTINGS)?;
        // CUR0_MODE premultiplied, no expansion, no degamma ROM; enable is
        // the position's.
        self.update(
            self.dpp(CUR0_CONTROL),
            CUR0_FIELDS & !ENABLE,
            PRE_MULTIPLIED << 4,
        )
    }
    /// `hubp2_cursor_set_position` + `dpp1_set_cursor_position`.
    fn position(&mut self, p: Placement) -> Result<(), Error> {
        let enable = u32::from(p.visible);
        self.update(self.hubp(CURSOR_CONTROL), ENABLE, enable)?;
        self.set(
            self.hubp(CURSOR_POSITION),
            (p.x & POSITION_MASK) << 16 | (p.y & POSITION_MASK),
        )?;
        self.set(
            self.hubp(CURSOR_HOT_SPOT),
            (p.hot_x & HOT_SPOT_MASK) << 16 | (p.hot_y & HOT_SPOT_MASK),
        )?;
        self.set(
            self.hubp(CURSOR_DST_OFFSET),
            p.dst_x_offset & DST_X_OFFSET_MASK,
        )?;
        self.update(self.dpp(CUR0_CONTROL), ENABLE, enable)
    }
    /// Program a new image (already in VRAM at `address`, pitch [`PITCH`])
    /// and place it, under one cursor lock.
    pub(crate) fn show(
        &mut self,
        address: u64,
        (width, height): (u32, u32),
        (x, y): (i32, i32),
        viewport: (u32, u32),
        clocks: (u32, u32),
    ) -> Result<Shown, Error> {
        if !(1..=CURSOR_MAX).contains(&width)
            || !(1..=CURSOR_MAX).contains(&height)
            || address == 0
            || address % 256 != 0
            || address >= 1 << 48
        {
            return Err(Error::Invalid);
        }
        let p = placement(x, y, (width, height), viewport, clocks);
        let result = self.locked(|e| {
            e.attributes(address, width, height)?;
            e.position(p)
        });
        // Whatever was written, the old image is no longer what is shown.
        self.shown = None;
        result?;
        let shown = Shown {
            address,
            width,
            height,
            x,
            y,
            placement: p,
        };
        self.shown = Some(shown);
        Ok(shown)
    }
    /// Move the shown image.
    pub(crate) fn move_to(
        &mut self,
        (x, y): (i32, i32),
        viewport: (u32, u32),
        clocks: (u32, u32),
    ) -> Result<Shown, Error> {
        let mut shown = self.shown.ok_or(Error::Invalid)?;
        let p = placement(x, y, (shown.width, shown.height), viewport, clocks);
        if p == shown.placement {
            shown.x = x;
            shown.y = y;
            self.shown = Some(shown);
            return Ok(shown);
        }
        let result = self.locked(|e| e.position(p));
        if result.is_err() {
            self.shown = None;
        }
        result?;
        shown.x = x;
        shown.y = y;
        shown.placement = p;
        self.shown = Some(shown);
        Ok(shown)
    }
    /// Disable the cursor in both HUBP and DPP (latched at the next VUPDATE).
    pub(crate) fn hide(&mut self) -> Result<(), Error> {
        self.shown = None;
        self.locked(|e| {
            e.update(e.hubp(CURSOR_CONTROL), ENABLE, 0)?;
            e.update(e.dpp(CUR0_CONTROL), ENABLE, 0)
        })
    }
}

/// The cursor registers of one owned DCN3.0 pipe.
#[derive(Debug)]
pub struct Cursor(Engine<Mmio>);
impl Cursor {
    /// # Safety
    /// The caller owns `pipe`'s HUBP, DPP and OPP-lock registers (the pipeline
    /// that lit the pipe) and serializes every access with that owner; the
    /// cursor surface it programs stays reserved until the cursor is hidden
    /// and a frame has latched.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pipe: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if profile != Profile::Navi22 || pipe >= profile.pipes() {
            return Err(Error::Unsupported);
        }
        let last = u64::from(profile.pipes() - 1);
        let dcn2 = profile.bank(gpu, 2, (CUR0_CONTROL + last * DPP_STRIDE) as u32)?;
        let dcn3 = profile.bank(gpu, 3, (CUR_VUPDATE_LOCK_SET + last * LOCK_STRIDE) as u32)?;
        Ok(Self(Engine {
            io: Mmio(gpu.regs),
            authority,
            dcn2,
            dcn3,
            pipe,
            shown: None,
        }))
    }
    pub fn shown(&self) -> Option<Shown> {
        self.0.shown
    }
    /// `viewport` is the plane's (width, height), `clocks` the DCHUB
    /// reference and pixel clocks in kHz.
    pub fn show(
        &mut self,
        address: u64,
        size: (u32, u32),
        at: (i32, i32),
        viewport: (u32, u32),
        clocks: (u32, u32),
    ) -> Result<Shown, Error> {
        self.0.show(address, size, at, viewport, clocks)
    }
    pub fn move_to(
        &mut self,
        at: (i32, i32),
        viewport: (u32, u32),
        clocks: (u32, u32),
    ) -> Result<Shown, Error> {
        self.0.move_to(at, viewport, clocks)
    }
    pub fn hide(&mut self) -> Result<(), Error> {
        self.0.hide()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_cursor_tests.rs"]
mod tests;
