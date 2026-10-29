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

// linux: n/a (dcn30_resource.c dcn30_resource_construct: dc->caps.max_cursor_size = 256)
pub const CURSOR_MAX: u32 = 256;
/// The image pitch in pixels, and CURSOR_PITCH's code for it.
pub const PITCH: u32 = 256; // linux: n/a (NARF image pitch)
                            // linux: n/a (CURSOR_PITCH_256_PIXELS, enum cursor_pitch in dc/inc/hw/hubp.h)
const PITCH_256: u32 = 2;
// linux-ctx: hdr=dcn seg=2
pub(crate) const CURSOR_CONTROL: u64 = 0x0678; // linux: mmCURSOR0_0_CURSOR_CONTROL
pub(crate) const CURSOR_SURFACE_ADDRESS: u64 = 0x0679; // linux: mmCURSOR0_0_CURSOR_SURFACE_ADDRESS
                                                       // linux: mmCURSOR0_0_CURSOR_SURFACE_ADDRESS_HIGH
pub(crate) const CURSOR_SURFACE_ADDRESS_HIGH: u64 = 0x067a;
pub(crate) const CURSOR_SIZE: u64 = 0x067b; // linux: mmCURSOR0_0_CURSOR_SIZE
pub(crate) const CURSOR_POSITION: u64 = 0x067c; // linux: mmCURSOR0_0_CURSOR_POSITION
pub(crate) const CURSOR_HOT_SPOT: u64 = 0x067d; // linux: mmCURSOR0_0_CURSOR_HOT_SPOT
pub(crate) const CURSOR_DST_OFFSET: u64 = 0x067f; // linux: mmCURSOR0_0_CURSOR_DST_OFFSET
pub(crate) const CURSOR_SETTINGS: u64 = 0x065c; // linux: mmHUBPREQ0_CURSOR_SETTINGS
                                                // linux: mmCURSOR0_1_CURSOR_CONTROL - mmCURSOR0_0_CURSOR_CONTROL
pub(crate) const HUBP_STRIDE: u64 = 0xdc;
pub(crate) const CUR0_CONTROL: u64 = 0x0cf1; // linux: mmCNVC_CUR0_CURSOR0_CONTROL
                                             // linux: mmCNVC_CUR1_CURSOR0_CONTROL - mmCNVC_CUR0_CURSOR0_CONTROL
pub(crate) const DPP_STRIDE: u64 = 0x16b;
// linux-ctx: hdr=dcn seg=3
pub(crate) const CUR_VUPDATE_LOCK_SET: u64 = 0x0513; // linux: mmCUR_VUPDATE_LOCK_SET0
pub(crate) const LOCK_STRIDE: u64 = 5; // linux: mmCUR_VUPDATE_LOCK_SET1 - mmCUR_VUPDATE_LOCK_SET0
                                       // linux-ctx: reset

// linux: CURSOR0_0_CURSOR_CONTROL__CURSOR_ENABLE_MASK
const ENABLE: u32 = 1;
/// CURSOR_MODE, CURSOR_2X_MAGNIFY, CURSOR_PITCH and CURSOR_LINES_PER_CHUNK.
// linux: CURSOR0_0_CURSOR_CONTROL__CURSOR_MODE_MASK | CURSOR0_0_CURSOR_CONTROL__CURSOR_2X_MAGNIFY_MASK | CURSOR0_0_CURSOR_CONTROL__CURSOR_PITCH_MASK | CURSOR0_0_CURSOR_CONTROL__CURSOR_LINES_PER_CHUNK_MASK
const CONTROL_FIELDS: u32 = 0x0000_0700 | 0x0000_0010 | 0x0003_0000 | 0x1f00_0000;
/// CURSOR_MODE_COLOR_PRE_MULTIPLIED_ALPHA (dc_cursor_color_format).
const PRE_MULTIPLIED: u32 = 2; // linux: CURSOR_MODE_COLOR_PRE_MULTIPLIED_ALPHA
                               // linux: CURSOR0_0_CURSOR_SIZE__CURSOR_WIDTH_MASK | CURSOR0_0_CURSOR_SIZE__CURSOR_HEIGHT_MASK
const SIZE_MASK: u32 = 0x01ff_01ff;
const POSITION_MASK: u32 = 0x3fff; // linux: CURSOR0_0_CURSOR_POSITION__CURSOR_Y_POSITION_MASK
const HOT_SPOT_MASK: u32 = 0xff; // linux: CURSOR0_0_CURSOR_HOT_SPOT__CURSOR_HOT_SPOT_Y_MASK
                                 // linux: CURSOR0_0_CURSOR_DST_OFFSET__CURSOR_DST_X_OFFSET_MASK
const DST_X_OFFSET_MASK: u32 = 0x1fff;
/// CURSOR0_CHUNK_HDL_ADJUST = 3, CURSOR0_DST_Y_OFFSET = 0.
// linux: 3 << HUBPREQ0_CURSOR_SETTINGS__CURSOR0_CHUNK_HDL_ADJUST__SHIFT
const SETTINGS: u32 = 3 << 8;
/// CUR0_ENABLE, CUR0_EXPANSION_MODE, CUR0_ROM_EN and CUR0_MODE.
// linux: CNVC_CUR0_CURSOR0_CONTROL__CUR0_ENABLE_MASK | CNVC_CUR0_CURSOR0_CONTROL__CUR0_EXPANSION_MODE_MASK | CNVC_CUR0_CURSOR0_CONTROL__CUR0_ROM_EN_MASK | CNVC_CUR0_CURSOR0_CONTROL__CUR0_MODE_MASK
const CUR0_FIELDS: u32 = 0x1 | 0x2 | 0x8 | 0x70;

/// CURSOR_LINES_PER_CHUNK for a 32-bpp colour cursor
/// (`hubp2_get_lines_per_chunk`, `enum cursor_lines_per_chunk`).
pub(crate) fn lines_per_chunk(width: u32) -> u32 {
    match width {
        // linux: n/a (CURSOR_LINE_PER_CHUNK_16, dc/inc/hw/hubp.h; hubp2_get_lines_per_chunk)
        0..=32 => 4,
        33..=64 => 3,  // linux: n/a (CURSOR_LINE_PER_CHUNK_8, dc/inc/hw/hubp.h)
        65..=128 => 2, // linux: n/a (CURSOR_LINE_PER_CHUNK_4, dc/inc/hw/hubp.h)
        _ => 1,        // linux: n/a (CURSOR_LINE_PER_CHUNK_2, dc/inc/hw/hubp.h)
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
    size: (u32, u32),
    (view_w, view_h): (u32, u32),
    clocks: (u32, u32),
) -> Placement {
    placement_in(x, y, size, (0, view_w, view_h), clocks)
}
/// [`placement`] for the pipe whose viewport starts at `view_x` (an ODM
/// slice): the position registers keep the stream coordinate, while
/// visibility and `CURSOR_DST_X_OFFSET` are relative to the slice
/// (`hubp2_cursor_set_position`'s `pos->x - param->viewport.x`).
pub fn placement_in(
    x: i32,
    y: i32,
    (width, height): (u32, u32),
    (view_x, view_w, view_h): (u32, u32, u32),
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
    let (sx, sy) = (px - i64::from(view_x) - hot_x, py - hot_y);
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
    /// ODM 2:1: each slice's pipe, `viewport_x` and width, left to right
    /// (the first is `pipe`).
    pub(crate) slices: Option<[(u8, u32, u32); 2]>,
    pub(crate) shown: Option<Shown>,
    /// What each programmed pipe was last placed at.
    pub(crate) placed: [Option<(u8, Placement)>; 2],
}
impl<I: Io> Engine<I> {
    fn hubp(&self, pipe: u8, reg: u64) -> u64 {
        self.dcn2 + (reg + u64::from(pipe) * HUBP_STRIDE) * 4
    }
    fn dpp(&self, pipe: u8, reg: u64) -> u64 {
        self.dcn2 + (reg + u64::from(pipe) * DPP_STRIDE) * 4
    }
    /// Each pipe's placement: one pipe over the whole `viewport`, or every
    /// ODM slice over its part of it.
    fn placements(
        &self,
        (x, y): (i32, i32),
        size: (u32, u32),
        (view_w, view_h): (u32, u32),
        clocks: (u32, u32),
    ) -> [Option<(u8, Placement)>; 2] {
        match self.slices {
            None => [
                Some((self.pipe, placement(x, y, size, (view_w, view_h), clocks))),
                None,
            ],
            Some(slices) => slices.map(|(pipe, view_x, width)| {
                Some((
                    pipe,
                    placement_in(x, y, size, (view_x, width, view_h), clocks),
                ))
            }),
        }
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
        self.set(lock, 1)?; // linux-lit: 1=CUR_VUPDATE_LOCK_SET0__CUR_VUPDATE_LOCK_SET_MASK
        let result = writes(self);
        result.and(self.set(lock, 0))
    }
    /// `hubp2_cursor_set_attributes` + `dpp3_set_cursor_attributes`.
    fn attributes(&mut self, pipe: u8, address: u64, width: u32, height: u32) -> Result<(), Error> {
        self.update(
            self.hubp(pipe, CURSOR_SURFACE_ADDRESS_HIGH),
            // linux-lit: 0xffff=CURSOR0_0_CURSOR_SURFACE_ADDRESS_HIGH__CURSOR_SURFACE_ADDRESS_HIGH_MASK
            0xffff,
            (address >> 32) as u32,
        )?;
        self.set(self.hubp(pipe, CURSOR_SURFACE_ADDRESS), address as u32)?;
        // linux-lit: 16=CURSOR0_0_CURSOR_SIZE__CURSOR_WIDTH__SHIFT
        self.update(
            self.hubp(pipe, CURSOR_SIZE),
            SIZE_MASK,
            width << 16 | height,
        )?;
        self.update(
            self.hubp(pipe, CURSOR_CONTROL),
            CONTROL_FIELDS,
            // linux-lit: 24=CURSOR0_0_CURSOR_CONTROL__CURSOR_LINES_PER_CHUNK__SHIFT
            // linux-lit: 16=CURSOR0_0_CURSOR_CONTROL__CURSOR_PITCH__SHIFT
            // linux-lit: 8=CURSOR0_0_CURSOR_CONTROL__CURSOR_MODE__SHIFT
            lines_per_chunk(width) << 24 | PITCH_256 << 16 | PRE_MULTIPLIED << 8,
        )?;
        self.set(self.hubp(pipe, CURSOR_SETTINGS), SETTINGS)?;
        // CUR0_MODE premultiplied, no expansion, no degamma ROM; enable is
        // the position's.
        self.update(
            self.dpp(pipe, CUR0_CONTROL),
            CUR0_FIELDS & !ENABLE,
            PRE_MULTIPLIED << 4, // linux-lit: 4=CNVC_CUR0_CURSOR0_CONTROL__CUR0_MODE__SHIFT
        )
    }
    /// `hubp2_cursor_set_position` + `dpp1_set_cursor_position`.
    fn position(&mut self, pipe: u8, p: Placement) -> Result<(), Error> {
        let enable = u32::from(p.visible);
        self.update(self.hubp(pipe, CURSOR_CONTROL), ENABLE, enable)?;
        self.set(
            self.hubp(pipe, CURSOR_POSITION),
            // linux-lit: 16=CURSOR0_0_CURSOR_POSITION__CURSOR_X_POSITION__SHIFT
            (p.x & POSITION_MASK) << 16 | (p.y & POSITION_MASK),
        )?;
        self.set(
            self.hubp(pipe, CURSOR_HOT_SPOT),
            // linux-lit: 16=CURSOR0_0_CURSOR_HOT_SPOT__CURSOR_HOT_SPOT_X__SHIFT
            (p.hot_x & HOT_SPOT_MASK) << 16 | (p.hot_y & HOT_SPOT_MASK),
        )?;
        self.set(
            self.hubp(pipe, CURSOR_DST_OFFSET),
            p.dst_x_offset & DST_X_OFFSET_MASK,
        )?;
        self.update(self.dpp(pipe, CUR0_CONTROL), ENABLE, enable)
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
            || address % 256 != 0 // linux: n/a (NARF validation: 256-byte cursor surface alignment)
            || address >= 1 << 48
        // linux: n/a (48-bit HUBP address space)
        {
            return Err(Error::Invalid);
        }
        let placed = self.placements((x, y), (width, height), viewport, clocks);
        let result = self.locked(|e| {
            for (pipe, p) in placed.into_iter().flatten() {
                e.attributes(pipe, address, width, height)?;
                e.position(pipe, p)?;
            }
            Ok(())
        });
        // Whatever was written, the old image is no longer what is shown.
        self.shown = None;
        self.placed = [None; 2];
        result?;
        let shown = Shown {
            address,
            width,
            height,
            x,
            y,
            placement: placed[0].map(|(_, p)| p).ok_or(Error::Invalid)?,
        };
        self.shown = Some(shown);
        self.placed = placed;
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
        let placed = self.placements((x, y), (shown.width, shown.height), viewport, clocks);
        if placed == self.placed {
            shown.x = x;
            shown.y = y;
            self.shown = Some(shown);
            return Ok(shown);
        }
        let result = self.locked(|e| {
            for (pipe, p) in placed.into_iter().flatten() {
                e.position(pipe, p)?;
            }
            Ok(())
        });
        if result.is_err() {
            self.shown = None;
            self.placed = [None; 2];
        }
        result?;
        shown.x = x;
        shown.y = y;
        shown.placement = placed[0].map(|(_, p)| p).ok_or(Error::Invalid)?;
        self.shown = Some(shown);
        self.placed = placed;
        Ok(shown)
    }
    /// Disable the cursor in both HUBP and DPP (latched at the next VUPDATE).
    pub(crate) fn hide(&mut self) -> Result<(), Error> {
        self.shown = None;
        self.placed = [None; 2];
        let pipes = match self.slices {
            None => [Some(self.pipe), None],
            Some([(a, ..), (b, ..)]) => [Some(a), Some(b)],
        };
        self.locked(|e| {
            for pipe in pipes.into_iter().flatten() {
                e.update(e.hubp(pipe, CURSOR_CONTROL), ENABLE, 0)?;
                e.update(e.dpp(pipe, CUR0_CONTROL), ENABLE, 0)?;
            }
            Ok(())
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
        if !profile.is_dcn30() || pipe >= profile.pipes() {
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
            slices: None,
            shown: None,
            placed: [None; 2],
        }))
    }
    /// Drive the cursor across ODM 2:1 `slices` (pipe, `viewport_x`,
    /// width; the first is this cursor's pipe), each pipe placed within its
    /// slice under the master OPP's cursor lock, as `dc_stream_set_cursor_*`
    /// programs every pipe of the stream.
    ///
    /// # Safety
    /// As [`Cursor::new`], for the secondary pipe's HUBP and DPP too.
    pub unsafe fn with_odm(
        mut self,
        gpu: &AmdGpu,
        slices: [(u8, u32, u32); 2],
    ) -> Result<Self, Error> {
        let pipes = Profile::resolve(gpu)?.pipes();
        if slices[0].0 != self.0.pipe
            || slices[1].0 == slices[0].0
            || slices[1].0 >= pipes
            || slices.iter().any(|&(_, _, width)| width == 0)
        {
            return Err(Error::Invalid);
        }
        self.0.slices = Some(slices);
        Ok(self)
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
