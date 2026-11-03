//! Display-14 framebuffer compression (FBC A) for the fixed Pipe-A
//! primary, enabled only while that plane scans out a KMS-owned GEM
//! framebuffer.
//!
//! Pinned source: Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! `i915/display/intel_fbc.c`, `intel_fbc_regs.h`,
//! `intel_display_regs.h` and `intel_display_wa.c`. Display 14 uses
//! `ivb_fbc_funcs` (no fences: `intel_fbc_has_fences` is false):
//!
//! - enable (`__intel_fbc_enable` → `intel_fbc_program_workarounds` +
//!   `ilk_fbc_program_cfb`): Wa_22014263786 (display 11.00–14.00) sets
//!   `DPFC_CHICKEN_FORCE_SLB_INVALIDATION`; wa_18038517565 (display >= 14)
//!   sets `MTL_DPFC_GATING_DIS` in `MTL_PIPE_CLKGATE_DIS2`; the CFB DSM
//!   offset goes to `ILK_DPFC_CB_BASE`.
//! - activate (`ivb_fbc_activate` then `intel_fbc_nuke`):
//!   `glk_fbc_program_cfb_stride` writes `GLK_FBC_STRIDE` (override in
//!   64-byte units per 4-line segment, divided by the limit, or 0), then
//!   `ILK_DPFC_CONTROL = DPFC_CTL_EN | limit` (no plane select below
//!   display 20), then `MSG_FBC_REND_STATE = FBC_REND_NUKE` and a posting
//!   read.
//! - deactivate (`ilk_fbc_deactivate`): clear `DPFC_CTL_EN` if set.
//! - disable (`__intel_fbc_disable`): wa_18038517565 undone.
//! - invalidate / flush (`intel_fbc_invalidate`, `__intel_fbc_flush`): a
//!   frontbuffer write deactivates; the flush nukes an active FBC or
//!   (re)activates an eligible one.
//!
//! Eligibility (`intel_fbc_check_plane`, display 14): visible, not
//! interlaced, no selective update, and no PSR1 — Wa_14016291713 refuses
//! PSR1 on display 14.00 A0–C0, and with no stepping readout this driver
//! refuses it on every display 14 part; XRGB8888 / XBGR8888 / RGB565;
//! any tiling and stride; no per-pixel alpha blending; plane at most
//! 5120x4096 and surface at most 8192x4096. Display 14 has no FBC CDCLK
//! term (`_intel_fbc_min_cdclk`) and `skl_watermark.c` has no FBC
//! watermark term, so no watermark or CDCLK hook is needed.
//! CFB: `_intel_fbc_cfb_stride` (512-aligned, at least
//! `skl_fbc_min_cfb_stride` with Wa_16011863758's +64), height capped at
//! 2560, limit from `find_compression_limit` (twice the size first, then
//! 1:1, 1:2, 1:4), placed below 2^28 in DSM.
//!
//! This driver never enables FBC on the console or boot framebuffer, and
//! never touches an FBC it did not activate: an inherited enable remains
//! the KMS takeover refusal it always was.

use crate::intel_gpu_aux::MmioWindow;

/// `ILK_DPFC_CB_BASE(INTEL_FBC_A)`.
pub const DPFC_CB_BASE: u64 = 0x43200;
/// `ILK_DPFC_CONTROL(INTEL_FBC_A)`.
pub const DPFC_CONTROL: u64 = 0x43208;
/// `DPFC_CTL_EN`.
pub const DPFC_CTL_EN: u32 = 1 << 31;
/// `DPFC_CTL_LIMIT_MASK` shift (bits 7:6).
pub const DPFC_CTL_LIMIT_SHIFT: u32 = 6;
/// `ILK_DPFC_STATUS2(INTEL_FBC_A)`.
pub const DPFC_STATUS2: u64 = 0x43214;
/// `ILK_DPFC_CHICKEN(INTEL_FBC_A)`.
pub const DPFC_CHICKEN: u64 = 0x43224;
/// `DPFC_CHICKEN_FORCE_SLB_INVALIDATION`.
pub const DPFC_CHICKEN_FORCE_SLB_INVALIDATION: u32 = 1 << 13;
/// `GLK_FBC_STRIDE(INTEL_FBC_A)`.
pub const FBC_STRIDE: u64 = 0x43228;
/// `FBC_STRIDE_OVERRIDE`.
pub const FBC_STRIDE_OVERRIDE: u32 = 1 << 15;
/// `FBC_STRIDE_MASK`.
pub const FBC_STRIDE_MASK: u32 = 0x7FFF;
/// `MSG_FBC_REND_STATE(INTEL_FBC_A)`.
pub const MSG_FBC_REND_STATE: u64 = 0x50380;
/// `FBC_REND_NUKE`.
pub const FBC_REND_NUKE: u32 = 1 << 2;
/// `MTL_PIPE_CLKGATE_DIS2(PIPE_A)`.
pub const PIPE_CLKGATE_DIS2: u64 = 0x60114;
/// `MTL_DPFC_GATING_DIS`.
pub const DPFC_GATING_DIS: u32 = 1 << 6;
/// `intel_fbc_max_cfb_height` for display >= 8.
pub const MAX_CFB_HEIGHT: u32 = 2560;
/// `intel_fbc_max_plane_size`, display >= 10.
pub const MAX_PLANE: (u32, u32) = (5120, 4096);
/// `intel_fbc_max_surface_size`, display >= 11.
pub const MAX_SURFACE: (u32, u32) = (8192, 4096);

/// Plane pixel formats as FBC classifies them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Xrgb8888,
    Xbgr8888,
    Rgb565,
    /// Anything else (XR30 included): `g4x_fbc_pixel_format_is_valid`
    /// refuses it.
    Other,
}

impl Format {
    fn cpp(self) -> u32 {
        if self == Format::Rgb565 {
            2
        } else {
            4
        }
    }
}

/// The plane facts eligibility depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plane {
    /// The plane scans out a KMS-owned GEM framebuffer (never the
    /// console or boot framebuffer).
    pub kms_owned: bool,
    pub format: Format,
    pub width: u32,
    pub height: u32,
    /// Source origin within the surface.
    pub x: u32,
    pub y: u32,
    pub stride_bytes: u32,
    pub per_pixel_alpha: bool,
    pub rotated_90: bool,
    pub interlaced: bool,
    pub psr1: bool,
    pub selective_update: bool,
}

/// Why FBC stays off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The console / boot framebuffer is scanned out.
    NotKmsOwned,
    Interlaced,
    SelectiveUpdate,
    /// Wa_14016291713 (no stepping readout: refused on all display 14).
    Psr1,
    Format,
    Rotation,
    PerPixelAlpha,
    PlaneSize,
    SurfaceSize,
    /// The CFB does not cover the plane at any admitted limit.
    CfbTooSmall,
}

/// `intel_fbc_check_plane` for display 14.
pub fn check_plane(plane: &Plane) -> Result<(), Refusal> {
    if !plane.kms_owned {
        return Err(Refusal::NotKmsOwned);
    }
    if plane.interlaced {
        return Err(Refusal::Interlaced);
    }
    if plane.selective_update {
        return Err(Refusal::SelectiveUpdate);
    }
    if plane.psr1 {
        return Err(Refusal::Psr1);
    }
    if plane.format == Format::Other {
        return Err(Refusal::Format);
    }
    if plane.format == Format::Rgb565 && plane.rotated_90 {
        return Err(Refusal::Rotation);
    }
    if plane.per_pixel_alpha {
        return Err(Refusal::PerPixelAlpha);
    }
    if plane.width > MAX_PLANE.0 || plane.height > MAX_PLANE.1 {
        return Err(Refusal::PlaneSize);
    }
    if plane.x + plane.width > MAX_SURFACE.0 || plane.y + plane.height > MAX_SURFACE.1 {
        return Err(Refusal::SurfaceSize);
    }
    Ok(())
}

/// `skl_fbc_min_cfb_stride` (display >= 11 adds Wa_16011863758's 64).
pub fn min_cfb_stride(cpp: u32, width: u32) -> u32 {
    // 1:4 is the worst-case limit; an FBC segment is 4 lines.
    const WORST_LIMIT: u32 = 4;
    const SEGMENT_LINES: u32 = 4;
    let segment = (width * cpp * SEGMENT_LINES / WORST_LIMIT + 64).div_ceil(512) * 512;
    segment * WORST_LIMIT / SEGMENT_LINES
}

/// `_intel_fbc_cfb_stride` for display >= 9 (bytes, 1:1 limit). The
/// plane stride is taken at the CFB cpp (`max(cpp, 4)`).
pub fn cfb_stride(format: Format, width: u32, stride_bytes: u32) -> u32 {
    let cpp = format.cpp().max(4);
    let plane_cfb_stride = stride_bytes / format.cpp() * cpp;
    plane_cfb_stride
        .div_ceil(512)
        .saturating_mul(512)
        .max(min_cfb_stride(cpp, width))
}

/// `_intel_fbc_cfb_size`.
pub fn cfb_size(format: Format, width: u32, height: u32, stride_bytes: u32) -> u64 {
    u64::from(height.min(MAX_CFB_HEIGHT)) * u64::from(cfb_stride(format, width, stride_bytes))
}

/// `intel_fbc_override_cfb_stride` (display 14: override only when the
/// aligned CFB stride differs from the plane's), in 64-byte units per
/// 4-line segment at 1:1.
pub fn override_stride(format: Format, width: u32, stride_bytes: u32) -> u16 {
    let cpp = format.cpp().max(4);
    let aligned = cfb_stride(format, width, stride_bytes);
    let plane = stride_bytes / format.cpp() * cpp;
    if aligned != plane {
        (aligned * 4 / 64) as u16
    } else {
        0
    }
}

/// `intel_fbc_min_limit`.
pub fn min_limit(format: Format) -> u32 {
    if format.cpp() == 2 {
        2
    } else {
        1
    }
}

/// `find_compression_limit`: first try twice the size at `min_limit`,
/// then halve per limit up to 1:4. `try_place` returns whether a range of
/// that many bytes could be placed. Returns `(limit, bytes)`.
pub fn find_compression_limit(
    size: u64,
    min_limit: u32,
    mut try_place: impl FnMut(u64) -> bool,
) -> Option<(u32, u64)> {
    let mut limit = min_limit;
    let mut size = size / u64::from(limit);
    size <<= 1;
    if try_place(size) {
        return Some((limit, size));
    }
    while limit <= 4 {
        size >>= 1;
        if try_place(size) {
            return Some((limit, size));
        }
        limit <<= 1;
    }
    None
}

/// The FBC A owner on the fixed Pipe-A primary. It only ever programs
/// what it placed and activated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fbc {
    cfb_offset: u32,
    cfb_bytes: u64,
    limit: u32,
    override_stride: u16,
    enabled: bool,
    active: bool,
}

impl Fbc {
    /// An owner over a placed CFB (`cfb_offset` within DSM, below 2^28).
    pub fn new(cfb_offset: u32, cfb_bytes: u64, limit: u32, override_stride: u16) -> Self {
        Self {
            cfb_offset,
            cfb_bytes,
            limit,
            override_stride,
            enabled: false,
            active: false,
        }
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// `intel_fbc_is_cfb_ok`.
    pub fn covers(&self, plane: &Plane) -> bool {
        min_limit(plane.format) <= self.limit
            && cfb_size(plane.format, plane.width, plane.height, plane.stride_bytes)
                <= u64::from(self.limit) * self.cfb_bytes
    }

    /// `intel_fbc_program_workarounds` + `ilk_fbc_program_cfb`.
    pub fn enable<M: MmioWindow + ?Sized>(&mut self, regs: &M) {
        if self.enabled {
            return;
        }
        let chicken = regs.read32(DPFC_CHICKEN);
        regs.write32(DPFC_CHICKEN, chicken | DPFC_CHICKEN_FORCE_SLB_INVALIDATION);
        let gate = regs.read32(PIPE_CLKGATE_DIS2);
        regs.write32(PIPE_CLKGATE_DIS2, gate | DPFC_GATING_DIS);
        regs.write32(DPFC_CB_BASE, self.cfb_offset);
        self.enabled = true;
    }

    /// `ivb_fbc_activate` followed by `intel_fbc_nuke`.
    pub fn activate<M: MmioWindow + ?Sized>(&mut self, regs: &M) {
        let stride = if self.override_stride != 0 {
            FBC_STRIDE_OVERRIDE | ((u32::from(self.override_stride) / self.limit) & FBC_STRIDE_MASK)
        } else {
            0
        };
        regs.write32(FBC_STRIDE, stride);
        let limit = match self.limit {
            2 => 1,
            4 => 2,
            _ => 0,
        };
        regs.write32(DPFC_CONTROL, DPFC_CTL_EN | (limit << DPFC_CTL_LIMIT_SHIFT));
        self.active = true;
        self.nuke(regs);
    }

    /// `snb_fbc_nuke`.
    pub fn nuke<M: MmioWindow + ?Sized>(&self, regs: &M) {
        regs.write32(MSG_FBC_REND_STATE, FBC_REND_NUKE);
        let _ = regs.read32(MSG_FBC_REND_STATE);
    }

    /// `ilk_fbc_deactivate`, only for an FBC this owner activated.
    pub fn deactivate<M: MmioWindow + ?Sized>(&mut self, regs: &M) {
        if !self.active {
            return;
        }
        let control = regs.read32(DPFC_CONTROL);
        if control != u32::MAX && control & DPFC_CTL_EN != 0 {
            regs.write32(DPFC_CONTROL, control & !DPFC_CTL_EN);
        }
        self.active = false;
    }

    /// `__intel_fbc_disable`: deactivate, then undo wa_18038517565.
    pub fn disable<M: MmioWindow + ?Sized>(&mut self, regs: &M) {
        self.deactivate(regs);
        if self.enabled {
            let gate = regs.read32(PIPE_CLKGATE_DIS2);
            if gate != u32::MAX {
                regs.write32(PIPE_CLKGATE_DIS2, gate & !DPFC_GATING_DIS);
            }
            self.enabled = false;
        }
    }

    /// `intel_fbc_invalidate`: a frontbuffer write or plane update is
    /// about to happen.
    pub fn invalidate<M: MmioWindow + ?Sized>(&mut self, regs: &M) {
        self.deactivate(regs);
    }

    /// `__intel_fbc_flush` after a latched flip or DIRTYFB: nuke an active
    /// FBC, or (re)activate when `plane` is eligible and covered; an
    /// ineligible plane disables. Returns the refusal, if any.
    pub fn flush<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        plane: &Plane,
    ) -> Result<(), Refusal> {
        if let Err(refusal) = check_plane(plane) {
            self.disable(regs);
            return Err(refusal);
        }
        if !self.covers(plane) {
            self.disable(regs);
            return Err(Refusal::CfbTooSmall);
        }
        if self.active {
            self.nuke(regs);
        } else {
            self.enable(regs);
            self.activate(regs);
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_fbc_tests.rs"]
mod tests;
