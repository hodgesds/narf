//! NVIDIA Turing+ display engine codec — clean-room.
//!
//! Reference: **`open-gpu-doc/manuals/turing/tu102/dev_disp.ref.txt`**
//! (Turing display) and the corresponding `dev_disp.ref.txt`
//! files for Ampere (`ga102`) and Ada (`ad102`). Cross-checked
//! against `open-gpu-doc/classes/disp` for the channel methods.
//!
//! License note: open-gpu-doc is MIT-licensed top-to-bottom.
//! **No GPL Linux `nouveau` source consulted.**
//!
//! ## Display engine model
//!
//! Turing+ display has:
//!
//! - **Heads** (typically 4) — each owns the raster timing
//!   generator + the OR (Output Resource) routing.
//! - **Windows** (typically 8 — 2 per head) — composition
//!   layers; window 0 of each head is the primary plane.
//! - **Cursors** — one per head, dedicated tiny plane.
//! - **OR (Output Resource) channels** — DAC / SOR / PIOR — bind
//!   a head to a physical port. SOR (Serial Output Resource)
//!   covers DP / HDMI / DSI / eDP on Turing+.
//!
//! All programming flows through **display channels**: a
//! head/window/cursor each owns a method-cell push buffer
//! exactly like the host FIFO push buffer in
//! [`super::nvidia_gpu_fifo`], with display-specific method
//! addresses + parameter layouts.
//!
//! ## Scope
//!
//! Codec only — produces register addresses + method-cell
//! encodings the Stage-3 driver core dispatches through MMIO.

use core::convert::TryFrom;

// ── Display engine MMIO layout (BAR0) ────────────────────────────
//
// Turing+ display engine occupies BAR0 `0x610000..0x680000`.
// Within that:

/// Display engine MMIO base.
pub const NV_PDISP_BASE: u64 = 0x0061_0000;
/// Per-head register window stride (`dev_disp.ref.txt`
/// §"NV_PDISP_HEAD").
pub const HEAD_STRIDE: u64 = 0x0000_2000;
/// Per-window register window stride.
pub const WINDOW_STRIDE: u64 = 0x0000_1000;

/// Identifies one head. Turing/Ampere/Ada all expose 4 heads
/// (some SKUs fuse off heads 2/3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Head {
    H0 = 0,
    H1 = 1,
    H2 = 2,
    H3 = 3,
}

impl Head {
    pub const fn base(self) -> u64 {
        NV_PDISP_BASE + 0x0001_0000 + (self as u64) * HEAD_STRIDE
    }
}

/// Identifies one composition window. 8 windows in total on
/// Turing+, indexed 0..8.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Window(pub u8);

impl Window {
    pub const fn base(self) -> u64 {
        NV_PDISP_BASE + 0x0003_0000 + (self.0 as u64) * WINDOW_STRIDE
    }
}

/// SOR (Serial Output Resource) — physical port / link
/// terminator. Turing+ has 4 SORs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Sor {
    Sor0 = 0,
    Sor1 = 1,
    Sor2 = 2,
    Sor3 = 3,
}

impl Sor {
    /// SOR control register base (`dev_disp.ref.txt` §"NV_PDISP_SOR").
    pub const fn base(self) -> u64 {
        NV_PDISP_BASE + 0x0006_0000 + (self as u64) * 0x0000_0800
    }
}

// ── OR protocol selectors ────────────────────────────────────────
//
// Source: `dev_disp.ref.txt` §"NV_PDISP_SOR_CONTROL — PROTOCOL".

/// SOR protocol field encoded in the head's `OR_CONTROL`
/// register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum OrProtocol {
    /// `LVDS_CUSTOM` — used by some embedded panels.
    LvdsCustom = 0x00,
    /// `SINGLE_TMDS_A` — HDMI single-link.
    SingleTmdsA = 0x01,
    /// `SINGLE_TMDS_B` — HDMI single-link via secondary lane set.
    SingleTmdsB = 0x02,
    /// `DUAL_TMDS` — HDMI dual-link.
    DualTmds = 0x05,
    /// `DP_A` — DisplayPort SST.
    DpSst = 0x08,
    /// `DP_A_MST` — DisplayPort MST.
    DpMst = 0x09,
    /// `DSI` — embedded MIPI DSI.
    Dsi = 0x0F,
}

impl OrProtocol {
    pub const fn encode(self) -> u32 {
        self as u32
    }
}

// ── Head method cells (display channel) ──────────────────────────
//
// The display channel push-buffer methods are documented in
// `open-gpu-doc/classes/disp/clc57d.h` (Turing class
// `NVC57D_*`). Stage-2 ships the load-bearing methods for a
// single-plane scanout.

/// `NVC57D_HEAD_SET_RASTER_SIZE(N)` — H total + V total.
/// Layout: bits[14:0] = h_total, bits[30:16] = v_total. Both in
/// pixel/scanline units.
pub const HEAD_SET_RASTER_SIZE: u16 = 0x2008;
/// `NVC57D_HEAD_SET_RASTER_SYNC_END(N)` — h_sync_end / v_sync_end.
pub const HEAD_SET_RASTER_SYNC_END: u16 = 0x200C;
/// `NVC57D_HEAD_SET_RASTER_BLANK_END(N)` — h_blank_end / v_blank_end.
pub const HEAD_SET_RASTER_BLANK_END: u16 = 0x2010;
/// `NVC57D_HEAD_SET_RASTER_BLANK_START(N)` — h_blank_start / v_blank_start.
pub const HEAD_SET_RASTER_BLANK_START: u16 = 0x2014;
/// `NVC57D_HEAD_SET_VIEWPORT_SIZE_OUT(N)` — output viewport size.
pub const HEAD_SET_VIEWPORT_SIZE_OUT: u16 = 0x2080;
/// `NVC57D_HEAD_SET_OR_CONTROL(N)` — bind head to OR + protocol.
pub const HEAD_SET_OR_CONTROL: u16 = 0x2160;
/// `NVC57D_HEAD_SET_PIXEL_CLOCK(N)` — pixel-clock target in kHz.
pub const HEAD_SET_PIXEL_CLOCK: u16 = 0x2018;

// ── Window method cells (window channel, NVC57E_*) ───────────────

/// `NVC57E_SET_PARAMS` — window parameters (format + colorspace).
pub const WINDOW_SET_PARAMS: u16 = 0x0500;
/// `NVC57E_SET_SIZE_IN` — input rectangle size.
pub const WINDOW_SET_SIZE_IN: u16 = 0x0508;
/// `NVC57E_SET_SIZE_OUT` — output rectangle size.
pub const WINDOW_SET_SIZE_OUT: u16 = 0x0500;
/// `NVC57E_SET_PRESENT_CONTROL` — present-time semantics.
pub const WINDOW_SET_PRESENT_CONTROL: u16 = 0x0708;
/// `NVC57E_SET_SURFACE_ADDRESS_LO_ISO` — primary surface phys low.
pub const WINDOW_SET_SURFACE_ADDRESS_LO_ISO: u16 = 0x0710;
/// `NVC57E_SET_SURFACE_ADDRESS_HI_ISO` — primary surface phys high.
pub const WINDOW_SET_SURFACE_ADDRESS_HI_ISO: u16 = 0x070C;

// ── Encoded shapes ───────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispError {
    /// Active size out of the documented 0..16384 range.
    TooLarge,
    /// Total smaller than active.
    BadTiming,
}

/// Display timings, in pixels / scanlines.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DisplayTiming {
    pub h_active: u16,
    pub v_active: u16,
    pub h_total: u16,
    pub v_total: u16,
    pub h_blank_start: u16,
    pub h_blank_end: u16,
    pub v_blank_start: u16,
    pub v_blank_end: u16,
    pub h_sync_end: u16,
    pub v_sync_end: u16,
    pub pixel_clock_khz: u32,
}

/// Encoded head-channel method-cell sequence for a mode-set.
/// Each entry is one (method, parameter) pair the driver core
/// pushes into the head channel.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct HeadModeset {
    pub raster_size: (u16, u32),
    pub raster_sync_end: (u16, u32),
    pub raster_blank_end: (u16, u32),
    pub raster_blank_start: (u16, u32),
    pub viewport_size_out: (u16, u32),
    pub pixel_clock: (u16, u32),
}

fn pack_h_v(h: u16, v: u16) -> u32 {
    (h as u32) | ((v as u32) << 16)
}

/// Build the head-channel method-cell parameters for a mode-set
/// programming the head with `t`. Caller dispatches each
/// (method, param) pair through the standard push-buffer
/// machinery.
pub fn build_head_modeset(t: &DisplayTiming) -> Result<HeadModeset, DispError> {
    if t.h_active == 0 || t.v_active == 0 || t.h_active > 16384 || t.v_active > 16384 {
        return Err(DispError::TooLarge);
    }
    if t.h_total < t.h_active || t.v_total < t.v_active {
        return Err(DispError::BadTiming);
    }
    Ok(HeadModeset {
        raster_size: (HEAD_SET_RASTER_SIZE, pack_h_v(t.h_total, t.v_total)),
        raster_sync_end: (
            HEAD_SET_RASTER_SYNC_END,
            pack_h_v(t.h_sync_end, t.v_sync_end),
        ),
        raster_blank_end: (
            HEAD_SET_RASTER_BLANK_END,
            pack_h_v(t.h_blank_end, t.v_blank_end),
        ),
        raster_blank_start: (
            HEAD_SET_RASTER_BLANK_START,
            pack_h_v(t.h_blank_start, t.v_blank_start),
        ),
        viewport_size_out: (HEAD_SET_VIEWPORT_SIZE_OUT, pack_h_v(t.h_active, t.v_active)),
        pixel_clock: (HEAD_SET_PIXEL_CLOCK, t.pixel_clock_khz),
    })
}

/// Build the OR-control parameter for binding a head to a
/// (SOR, protocol) pair. Encoding: bits[3:0] = SOR index,
/// bits[15:8] = protocol.
pub fn build_or_control(sor: Sor, protocol: OrProtocol) -> u32 {
    (sor as u32) | (protocol.encode() << 8)
}

impl TryFrom<u8> for Window {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        if v < 8 {
            Ok(Window(v))
        } else {
            Err(())
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn timing() -> DisplayTiming {
        DisplayTiming {
            h_active: 1920,
            v_active: 1080,
            h_total: 2200,
            v_total: 1125,
            h_blank_start: 1920,
            h_blank_end: 2200,
            v_blank_start: 1080,
            v_blank_end: 1125,
            h_sync_end: 2052,
            v_sync_end: 1089,
            pixel_clock_khz: 148_500,
        }
    }

    fn smoke_head_base_strides() -> TestResult {
        if Head::H0.base() != NV_PDISP_BASE + 0x0001_0000 {
            return TestResult::Fail("Head 0 base wrong");
        }
        if Head::H1.base() - Head::H0.base() != HEAD_STRIDE {
            return TestResult::Fail("head stride wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_disp", smoke_head_base_strides);

    fn smoke_or_protocol_encoding() -> TestResult {
        let v = build_or_control(Sor::Sor1, OrProtocol::DpSst);
        if v & 0xF != 1 {
            return TestResult::Fail("SOR index lost");
        }
        if (v >> 8) & 0xFF != OrProtocol::DpSst.encode() {
            return TestResult::Fail("protocol field wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_disp", smoke_or_protocol_encoding);

    fn smoke_head_modeset_layout() -> TestResult {
        let m = match build_head_modeset(&timing()) {
            Ok(m) => m,
            Err(_) => return TestResult::Fail("clean DT rejected"),
        };
        if m.raster_size.0 != HEAD_SET_RASTER_SIZE {
            return TestResult::Fail("raster size method addr wrong");
        }
        let want = (2200u32) | ((1125u32) << 16);
        if m.raster_size.1 != want {
            return TestResult::Fail("raster size payload packing wrong");
        }
        if m.viewport_size_out.1 != ((1920u32) | (1080u32 << 16)) {
            return TestResult::Fail("viewport size payload wrong");
        }
        if m.pixel_clock.1 != 148_500 {
            return TestResult::Fail("pixel clock parameter lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_disp", smoke_head_modeset_layout);

    fn smoke_head_modeset_rejects_bad_total() -> TestResult {
        let mut t = timing();
        t.h_total = 100; // less than h_active
        match build_head_modeset(&t) {
            Err(DispError::BadTiming) => TestResult::Pass,
            _ => TestResult::Fail("h_total < h_active must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_disp",
        smoke_head_modeset_rejects_bad_total
    );

    fn smoke_window_index_bounds() -> TestResult {
        if Window::try_from(8).is_ok() {
            return TestResult::Fail("only windows 0..8 documented");
        }
        let w = Window::try_from(7).expect("valid index");
        if w.base() <= Head::H3.base() {
            return TestResult::Fail("window base must lie above heads");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_disp", smoke_window_index_bounds);
}
