//! Pipe / transcoder / plane register codec — clean-room.
//!
//! Reference: **Tiger Lake PRM Vol. 14 §"Display Engine"** —
//! pipes (`PIPE_*`), transcoders (`TRANS_*`), and primary planes
//! (`PLANE_*`). Cross-checked against the Alder Lake PRM and the
//! Meteor Lake display PRM (offsets stable across Gen12 / Xe-LPG).
//!
//! ## Display engine model
//!
//! Gen12 has **3 pipes** (A, B, C, plus D on some SKUs) and **5
//! transcoders** (A, B, C, D, EDP). A pipe owns the *raster
//! geometry* — source rectangle and pixel pipeline — while a
//! transcoder owns the *output timing* (HTOTAL / VTOTAL / sync
//! pulses) and routes through a DDI to a physical port.
//!
//! Each pipe carries up to 7 planes. Plane 1 is the "primary"
//! plane — full-pipe scanout from VRAM. Stage-2 ships only the
//! primary-plane registers; cursor / overlay / sprite planes
//! land later.
//!
//! ## Scope
//!
//! Codec layer — produces register addresses + value encodings.
//! The actual MMIO writes live in the Stage-3 driver core.

use core::convert::TryFrom;

// ── Pipe / transcoder identifiers ────────────────────────────────

/// Display pipes available on Gen12. PRM Vol. 14 §"Pipes".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Pipe {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
}

/// Transcoders available on Gen12. PRM Vol. 14 §"Transcoders".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Transcoder {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
    /// Embedded DisplayPort transcoder (eDP panel path).
    Edp = 4,
}

// ── The display engine has *two* per-pipe register regions ───────
//
// They are both indexed by pipe with a 0x1000 stride, which makes it
// easy to assume there is only one. There is not, and the split does
// not follow the register names:
//
//   0x60000  transcoder timing — TRANS_HTOTAL and friends, plus
//            PIPE_SRCSZ at +0x1C and TRANS_DDI_FUNC_CTL at +0x400.
//   0x70000  pipe and plane    — TRANSCONF at +0x008 (despite the
//            "TRANS" name) and the universal plane block at +0x180.
//
// Cross-referenced against i915 `intel_display_regs.h`
// (`_TRANS_HTOTAL_A` 0x60000, `_PIPEASRC` 0x6001c, `_TRANSACONF`
// 0x70008, `_TRANS_DDI_FUNC_CTL_A` 0x60400) and
// `skl_universal_plane_regs.h` (`_PLANE_CTL_1_A` 0x70180).

/// Base of the transcoder timing region.
pub const TRANS_TIMING_BASE: u64 = 0x0006_0000;
/// Base of the pipe / plane region.
pub const PIPE_PLANE_BASE: u64 = 0x0007_0000;

impl Pipe {
    /// Per-pipe MMIO offset stride. Each pipe is exactly `0x1000`
    /// bytes wide in both regions (PRM Vol. 14 §"Pipe MMIO Map").
    pub const STRIDE: u64 = 0x1000;

    /// Base of this pipe's **pipe/plane** block — `TRANSCONF` and the
    /// plane registers. Pipe A starts at `0x70000`.
    pub const fn base(self) -> u64 {
        PIPE_PLANE_BASE + (self as u64) * Self::STRIDE
    }

    /// Base of this pipe's **transcoder timing** block, which is
    /// where `PIPE_SRCSZ` lives despite its name. Pipe A starts at
    /// `0x60000`.
    pub const fn trans_base(self) -> u64 {
        TRANS_TIMING_BASE + (self as u64) * Self::STRIDE
    }
}

impl Transcoder {
    pub const STRIDE: u64 = 0x1000;
    /// Base of the per-transcoder **timing** block. Transcoder A
    /// starts at `0x60000`; B..D follow at +0x1000; EDP lives
    /// separately at `0x6F000`.
    pub const fn base(self) -> u64 {
        match self {
            Transcoder::A => 0x0006_0000,
            Transcoder::B => 0x0006_1000,
            Transcoder::C => 0x0006_2000,
            Transcoder::D => 0x0006_3000,
            Transcoder::Edp => 0x0006_F000,
        }
    }

    /// Base of the block holding this transcoder's `TRANSCONF`.
    ///
    /// `TRANSCONF` is named for the transcoder but lives in the pipe
    /// region at `0x70008`, not beside the timing registers. Using
    /// [`Self::base`] for it lands on `TRANS_HSYNC` instead.
    ///
    /// The `Edp` arm mirrors the timing block's `0x6F000` offset.
    /// Gen12 removed the separate EDP transcoder, and this driver
    /// only supports Gen12 and later, so that arm is unreachable in
    /// practice and unverified against hardware.
    pub const fn conf_base(self) -> u64 {
        match self {
            Transcoder::A => 0x0007_0000,
            Transcoder::B => 0x0007_1000,
            Transcoder::C => 0x0007_2000,
            Transcoder::D => 0x0007_3000,
            Transcoder::Edp => 0x0007_F000,
        }
    }
}

// ── Pipe registers (TGL PRM Vol. 14 §"PIPE_*") ───────────────────

/// `PIPE_SRCSZ` — source size for the pipe. Relative to
/// [`Pipe::trans_base`], *not* [`Pipe::base`]: i915 calls it
/// `_PIPEASRC` at 0x6001c, in the timing region.
/// Layout: bits[28:16] = horizontal-1, bits[12:0] = vertical-1.
pub const PIPE_SRCSZ_OFFSET: u64 = 0x001C;
/// `PIPECONF` (legacy name) / `PIPE_TRANS_CONF` on Gen12 — top-
/// level pipe enable and pixel format.
pub const PIPECONF_OFFSET: u64 = 0x0008;

/// `PIPECONF[31]` — pipe enable.
pub const PIPECONF_ENABLE: u32 = 1 << 31;
/// `PIPECONF[30]` — pipe state (read-only).
pub const PIPECONF_STATE: u32 = 1 << 30;

// ── Transcoder registers (TGL PRM Vol. 14 §"TRANS_*") ────────────

/// `TRANS_HTOTAL` — horizontal total.
/// Layout: bits[28:16] = htotal-1, bits[12:0] = hactive-1.
pub const TRANS_HTOTAL_OFFSET: u64 = 0x0000;
/// `TRANS_HBLANK` — horizontal blank.
/// Layout: bits[28:16] = hblank-end-1, bits[12:0] = hblank-start-1.
pub const TRANS_HBLANK_OFFSET: u64 = 0x0004;
/// `TRANS_HSYNC` — horizontal sync pulse.
pub const TRANS_HSYNC_OFFSET: u64 = 0x0008;
/// `TRANS_VTOTAL` — vertical total.
pub const TRANS_VTOTAL_OFFSET: u64 = 0x000C;
/// `TRANS_VBLANK` — vertical blank.
pub const TRANS_VBLANK_OFFSET: u64 = 0x0010;
/// `TRANS_VSYNC` — vertical sync pulse.
pub const TRANS_VSYNC_OFFSET: u64 = 0x0014;
/// `TRANS_DDI_FUNC_CTL` — bind transcoder to DDI port.
pub const TRANS_DDI_FUNC_CTL_OFFSET: u64 = 0x0400;

/// `TRANS_DDI_FUNC_CTL[31]` — function enable.
pub const TRANS_DDI_FUNC_CTL_ENABLE: u32 = 1 << 31;
/// DDI selection bits[30:27] of `TRANS_DDI_FUNC_CTL`.
pub const TRANS_DDI_FUNC_CTL_DDI_SHIFT: u32 = 27;
/// Mode select bits[26:24] (HDMI / DVI / DP-SST / DP-MST / FDI).
pub const TRANS_DDI_FUNC_CTL_MODE_SHIFT: u32 = 24;
pub const TRANS_DDI_MODE_HDMI: u32 = 0b000 << TRANS_DDI_FUNC_CTL_MODE_SHIFT;
pub const TRANS_DDI_MODE_DVI: u32 = 0b001 << TRANS_DDI_FUNC_CTL_MODE_SHIFT;
pub const TRANS_DDI_MODE_DP_SST: u32 = 0b010 << TRANS_DDI_FUNC_CTL_MODE_SHIFT;
pub const TRANS_DDI_MODE_DP_MST: u32 = 0b011 << TRANS_DDI_FUNC_CTL_MODE_SHIFT;

// ── Plane registers (SKL+ universal plane) ───────────────────────
//
// The plane block sits inside the *pipe* region at [`Pipe::base`],
// one 0x100-byte block per plane starting at +0x180. Cross-checked
// against i915 `skl_universal_plane_regs.h`: `_PLANE_CTL_1_A`
// 0x70180, `_PLANE_STRIDE_1_A` 0x70188, `_PLANE_POS_1_A` 0x7018c,
// `_PLANE_SIZE_1_A` 0x70190, `_PLANE_SURF_1_A` 0x7019c,
// `_PLANE_OFFSET_1_A` 0x701a4, with `_PLANE_CTL_2_A` at 0x70280
// giving the per-plane stride and `_PLANE_CTL_1_B` at 0x71180 the
// per-pipe one.

/// Primary plane (plane 1) offset relative to its pipe base.
pub const PLANE_PRIMARY_OFFSET: u64 = 0x0180;
/// Stride between consecutive planes within one pipe.
pub const PLANE_STRIDE_BETWEEN_PLANES: u64 = 0x0100;

/// `PLANE_CTL` — top-level plane enable + pixel format.
pub const PLANE_CTL_OFFSET: u64 = 0x0000;
/// `PLANE_STRIDE` — surface stride in 64-byte units.
pub const PLANE_STRIDE_OFFSET: u64 = 0x0008;
/// `PLANE_POS` — destination position (for sub-pipe planes).
pub const PLANE_POS_OFFSET: u64 = 0x000C;
/// `PLANE_SIZE` — destination size.
pub const PLANE_SIZE_OFFSET: u64 = 0x0010;
/// `PLANE_SURF` — primary-surface address (full GPU virtual
/// address; stride decoupled).
pub const PLANE_SURF_OFFSET: u64 = 0x001C;
/// `PLANE_OFFSET` — pan-and-scan offset within `PLANE_SURF`.
pub const PLANE_OFFSET_OFFSET: u64 = 0x0024;

/// `PLANE_CTL[31]` — plane enable.
pub const PLANE_CTL_ENABLE: u32 = 1 << 31;

/// Pixel-format encoding in `PLANE_CTL[27:23]`.
/// Source: TGL PRM Vol. 14 §"PLANE_CTL — Source Pixel Format".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    /// 8-bit indexed.
    Indexed8 = 0b01100,
    /// 8:8:8:8 ARGB / XRGB. The "X" form (PIPE only sees opaque
    /// 32-bpp scanout) is selected by the alpha disable bit.
    Argb8888 = 0b00100,
    /// 5:6:5 RGB.
    Rgb565 = 0b01110,
    /// 10:10:10:2 ARGB / XRGB (HDR scanout).
    Rgb2101010 = 0b00010,
    /// FP16 RGBA (HDR composite path).
    Fp16Rgba = 0b10010,
}

impl PixelFormat {
    pub const fn encode_for_plane_ctl(self) -> u32 {
        (self as u32) << 23
    }
}

// ── Encoded mode shape ───────────────────────────────────────────

/// Display timings, in pixels / scanlines.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DisplayTiming {
    pub hactive: u16,
    pub hblank_start: u16,
    pub hblank_end: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub vactive: u16,
    pub vblank_start: u16,
    pub vblank_end: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PipeError {
    /// Active size exceeds the 8192-pixel display engine maximum.
    TooLarge,
    /// Stride isn't a multiple of 64 bytes (display engine
    /// requires 64-byte plane-stride alignment).
    BadStride,
    /// Total smaller than active.
    BadTiming,
}

/// One programmed transcoder: the `TRANS_*` register values to
/// write at the transcoder's MMIO base.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TranscoderProgram {
    pub htotal: u32,
    pub hblank: u32,
    pub hsync: u32,
    pub vtotal: u32,
    pub vblank: u32,
    pub vsync: u32,
}

/// One programmed pipe.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PipeProgram {
    pub srcsz: u32,
    pub pipeconf: u32,
}

/// One programmed primary plane.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PrimaryPlaneProgram {
    pub plane_ctl: u32,
    /// Stride encoded in `PLANE_STRIDE` (64-byte units).
    pub plane_stride: u32,
    pub plane_size: u32,
    pub plane_surf: u32,
    pub plane_offset: u32,
}

fn pack_total_active(total: u16, active: u16) -> Result<u32, PipeError> {
    if total < active || total > 8192 || active == 0 {
        return Err(PipeError::BadTiming);
    }
    let total_m1 = (total - 1) as u32;
    let active_m1 = (active - 1) as u32;
    Ok((total_m1 << 16) | active_m1)
}

fn pack_pair(end: u16, start: u16) -> u32 {
    (((end.saturating_sub(1)) as u32) << 16) | ((start.saturating_sub(1)) as u32)
}

/// Build the `TRANS_HTOTAL/HBLANK/HSYNC/VTOTAL/VBLANK/VSYNC`
/// values for `t`.
pub fn build_transcoder(t: &DisplayTiming) -> Result<TranscoderProgram, PipeError> {
    let htotal = pack_total_active(t.htotal, t.hactive)?;
    let vtotal = pack_total_active(t.vtotal, t.vactive)?;
    let hblank = pack_pair(t.hblank_end, t.hblank_start);
    let vblank = pack_pair(t.vblank_end, t.vblank_start);
    let hsync = pack_pair(t.hsync_end, t.hsync_start);
    let vsync = pack_pair(t.vsync_end, t.vsync_start);
    Ok(TranscoderProgram {
        htotal,
        hblank,
        hsync,
        vtotal,
        vblank,
        vsync,
    })
}

/// Build `PIPE_SRCSZ` + `PIPECONF` for a pipe driving `t`.
/// `PIPECONF.enable` is set; the caller may clear it before
/// programming and assert it as the last write to start scanout.
pub fn build_pipe(t: &DisplayTiming) -> Result<PipeProgram, PipeError> {
    if t.hactive == 0 || t.vactive == 0 || t.hactive > 8192 || t.vactive > 8192 {
        return Err(PipeError::TooLarge);
    }
    let srcsz = (((t.hactive - 1) as u32) << 16) | ((t.vactive - 1) as u32);
    Ok(PipeProgram {
        srcsz,
        pipeconf: PIPECONF_ENABLE,
    })
}

/// Build the primary-plane registers for a linear scanout from
/// `surface_addr` (GPU virtual address, post-GTT) at
/// `(active_w, active_h)` with `stride_bytes` bytes per scanline
/// in `format`.
pub fn build_primary_plane(
    active_w: u16,
    active_h: u16,
    stride_bytes: u32,
    surface_addr: u32,
    format: PixelFormat,
) -> Result<PrimaryPlaneProgram, PipeError> {
    if active_w == 0 || active_h == 0 || active_w > 8192 || active_h > 8192 {
        return Err(PipeError::TooLarge);
    }
    if stride_bytes == 0 || stride_bytes & 0x3F != 0 {
        return Err(PipeError::BadStride);
    }
    let plane_ctl = PLANE_CTL_ENABLE | format.encode_for_plane_ctl();
    let plane_stride = stride_bytes >> 6; // 64-byte units
    let plane_size = (((active_h - 1) as u32) << 16) | ((active_w - 1) as u32);
    Ok(PrimaryPlaneProgram {
        plane_ctl,
        plane_stride,
        plane_size,
        plane_surf: surface_addr & !0xFFF, // 4 KiB aligned
        plane_offset: 0,
    })
}

impl TryFrom<u8> for Pipe {
    type Error = PipeError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => Pipe::A,
            1 => Pipe::B,
            2 => Pipe::C,
            3 => Pipe::D,
            _ => return Err(PipeError::TooLarge),
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn dt() -> DisplayTiming {
        // 1920x1080 @ 60 Hz CVT-ish (illustrative, not VESA-exact).
        DisplayTiming {
            hactive: 1920,
            hblank_start: 1920,
            hblank_end: 2200,
            hsync_start: 2008,
            hsync_end: 2052,
            htotal: 2200,
            vactive: 1080,
            vblank_start: 1080,
            vblank_end: 1125,
            vsync_start: 1084,
            vsync_end: 1089,
            vtotal: 1125,
        }
    }

    fn smoke_pipe_base_strides() -> TestResult {
        // The pipe/plane region, where TRANSCONF and the planes live.
        if Pipe::A.base() != 0x70000 || Pipe::B.base() != 0x71000 {
            return TestResult::Fail("pipe/plane base wrong");
        }
        // The transcoder timing region, where PIPE_SRCSZ lives.
        if Pipe::A.trans_base() != 0x60000 || Pipe::B.trans_base() != 0x61000 {
            return TestResult::Fail("transcoder timing base wrong");
        }
        if Transcoder::Edp.base() != 0x6F000 {
            return TestResult::Fail("EDP transcoder base wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pipes", smoke_pipe_base_strides);

    /// Absolute addresses, cross-checked against i915. The two
    /// per-pipe regions share a 0x1000 stride, so a register put in
    /// the wrong one still lands somewhere plausible — these pin the
    /// values rather than the arithmetic.
    fn smoke_display_register_addresses_match_i915() -> TestResult {
        // intel_display_regs.h
        if Transcoder::A.base() + TRANS_HTOTAL_OFFSET != 0x60000 {
            return TestResult::Fail("_TRANS_HTOTAL_A is 0x60000");
        }
        if Transcoder::A.base() + TRANS_HSYNC_OFFSET != 0x60008 {
            return TestResult::Fail("_TRANS_HSYNC_A is 0x60008");
        }
        if Pipe::A.trans_base() + PIPE_SRCSZ_OFFSET != 0x6001C {
            return TestResult::Fail("_PIPEASRC is 0x6001c");
        }
        if Transcoder::A.base() + TRANS_DDI_FUNC_CTL_OFFSET != 0x60400 {
            return TestResult::Fail("_TRANS_DDI_FUNC_CTL_A is 0x60400");
        }
        // TRANSCONF is named for the transcoder but lives in the pipe
        // region. Reaching it through the timing base would land on
        // TRANS_HSYNC, which is the bug this pins shut.
        if Transcoder::A.conf_base() + PIPECONF_OFFSET != 0x70008 {
            return TestResult::Fail("_TRANSACONF is 0x70008");
        }
        if Pipe::A.base() + PIPECONF_OFFSET != 0x70008 {
            return TestResult::Fail("pipe A TRANSCONF disagrees with the transcoder path");
        }
        if Transcoder::A.conf_base() + PIPECONF_OFFSET == Transcoder::A.base() + TRANS_HSYNC_OFFSET
        {
            return TestResult::Fail("TRANSCONF still collides with TRANS_HSYNC");
        }

        // skl_universal_plane_regs.h
        let plane = Pipe::A.base() + PLANE_PRIMARY_OFFSET;
        if plane + PLANE_CTL_OFFSET != 0x70180 {
            return TestResult::Fail("_PLANE_CTL_1_A is 0x70180");
        }
        if plane + PLANE_STRIDE_OFFSET != 0x70188 {
            return TestResult::Fail("_PLANE_STRIDE_1_A is 0x70188");
        }
        if plane + PLANE_POS_OFFSET != 0x7018C {
            return TestResult::Fail("_PLANE_POS_1_A is 0x7018c");
        }
        if plane + PLANE_SIZE_OFFSET != 0x70190 {
            return TestResult::Fail("_PLANE_SIZE_1_A is 0x70190");
        }
        if plane + PLANE_SURF_OFFSET != 0x7019C {
            return TestResult::Fail("_PLANE_SURF_1_A is 0x7019c");
        }
        if plane + PLANE_OFFSET_OFFSET != 0x701A4 {
            return TestResult::Fail("_PLANE_OFFSET_1_A is 0x701a4");
        }
        // Per-plane and per-pipe strides.
        if plane + PLANE_STRIDE_BETWEEN_PLANES != 0x70280 {
            return TestResult::Fail("_PLANE_CTL_2_A is 0x70280");
        }
        if Pipe::B.base() + PLANE_PRIMARY_OFFSET != 0x71180 {
            return TestResult::Fail("_PLANE_CTL_1_B is 0x71180");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pipes",
        smoke_display_register_addresses_match_i915
    );

    /// The two per-pipe regions must not overlap for any pipe.
    fn smoke_pipe_regions_are_disjoint() -> TestResult {
        for p in [Pipe::A, Pipe::B, Pipe::C, Pipe::D] {
            if p.trans_base() >= PIPE_PLANE_BASE {
                return TestResult::Fail("a timing base reached into the pipe region");
            }
            if p.base() < PIPE_PLANE_BASE {
                return TestResult::Fail("a pipe base fell into the timing region");
            }
        }
        if TRANS_TIMING_BASE != 0x60000 || PIPE_PLANE_BASE != 0x70000 {
            return TestResult::Fail("region bases wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pipes",
        smoke_pipe_regions_are_disjoint
    );

    fn smoke_transcoder_program() -> TestResult {
        let p = match build_transcoder(&dt()) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean DT rejected"),
        };
        // HTOTAL packs (htotal-1) << 16 | (hactive-1).
        let want_h = ((2200u32 - 1) << 16) | (1920 - 1);
        if p.htotal != want_h {
            return TestResult::Fail("HTOTAL packing wrong");
        }
        let want_v = ((1125u32 - 1) << 16) | (1080 - 1);
        if p.vtotal != want_v {
            return TestResult::Fail("VTOTAL packing wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pipes", smoke_transcoder_program);

    fn smoke_pipe_program() -> TestResult {
        let p = match build_pipe(&dt()) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean DT rejected"),
        };
        if p.pipeconf & PIPECONF_ENABLE == 0 {
            return TestResult::Fail("pipe enable not asserted");
        }
        if p.srcsz != ((1920u32 - 1) << 16) | (1080 - 1) {
            return TestResult::Fail("PIPE_SRCSZ packing wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pipes", smoke_pipe_program);

    fn smoke_primary_plane_program() -> TestResult {
        let p = match build_primary_plane(1920, 1080, 1920 * 4, 0x0010_0000, PixelFormat::Argb8888)
        {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        if p.plane_ctl & PLANE_CTL_ENABLE == 0 {
            return TestResult::Fail("plane enable not asserted");
        }
        if p.plane_stride != (1920 * 4) >> 6 {
            return TestResult::Fail("stride 64B encoding wrong");
        }
        if p.plane_surf != 0x0010_0000 {
            return TestResult::Fail("surface addr wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pipes", smoke_primary_plane_program);

    fn smoke_primary_plane_rejects_bad_stride() -> TestResult {
        match build_primary_plane(1920, 1080, 1921, 0x1000, PixelFormat::Argb8888) {
            Err(PipeError::BadStride) => TestResult::Pass,
            _ => TestResult::Fail("non-64B stride must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pipes",
        smoke_primary_plane_rejects_bad_stride
    );
}
