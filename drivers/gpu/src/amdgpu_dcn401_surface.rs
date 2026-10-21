//! Owned linear RGB surface staging for native DCN401. Linux references:
//! hubp401_program_surface_config, hubp401_set_viewport and
//! hubp401_program_surface_flip_and_addr. Fetch remains blank and disconnected.
use super::*;
use crate::amdgpu_dcn401_spl as spl;
use crate::amdgpu_vram::{Pool, Reservation};
use core::sync::atomic::{fence, Ordering};
#[path = "amdgpu_dcn401_surface_release.rs"]
mod release;
#[path = "amdgpu_dcn401_vm.rs"]
mod vm;
pub use vm::MemoryApplied;
#[path = "amdgpu_dcn401_dpp.rs"]
mod dpp;
pub use dpp::DppApplied;
#[cfg(feature = "kernel-test")]
pub(in crate::amdgpu_dcn401_otg) use dpp::{post_csc_set_b, post_csc_words, CURSOR_MATRIX_WORD};
#[path = "amdgpu_dcn401_mpc.rs"]
mod mpc;
pub use mpc::MpcApplied;
#[path = "amdgpu_dcn401_requestor.rs"]
mod requestor;
pub use requestor::{RequestorApplied, MAX_OVERLAYS};
#[path = "amdgpu_dcn401_deadline.rs"]
mod deadline;
pub use deadline::DeadlinesApplied;
#[path = "amdgpu_dcn401_cursor.rs"]
mod cursor;
pub use cursor::{cursor_mode, plane_scale, CursorApplied, CursorMode, CursorUnder, CURSOR_MAX};
#[path = "amdgpu_dcn401_color.rs"]
mod color;
#[path = "amdgpu_dcn401_flip.rs"]
mod flip;
#[path = "amdgpu_dcn401_plane_update.rs"]
mod plane_update;
#[path = "amdgpu_dcn401_scanout.rs"]
mod scanout;
pub use color::{ColorProgram, GamutProgram, InputTf, OgamProgram, PipeColor, PreDegam};
pub use flip::{ExternalSurface, FlipDone, FlipSource};
pub use plane_update::{
    plane_update_type, planes_update_type, Cleared, LivePlanes, PlaneContent, PlanesUpdated,
    UpdateType,
};
pub use scanout::{
    LivePipe, OverlayScanout, ScanoutPosition, ScanoutRunning, ScanoutUnderflow, VblankPhase,
};

/// A scanout format: the DRM fourccs amdgpu_dm offers on DCN4.0.1 planes
/// that this path programs, each mapped to its DC surface format as
/// amdgpu_dm's fill_dc_plane_info_and_addr does (X and A variants share
/// one; only the blending differs): packed RGB, and the two-plane 4:2:0
/// video formats (DC's VIDEO_420_YCrCb for NV12 and VIDEO_420_10bpc_YCrCb
/// for P010, as amdgpu_dm names them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceFormat {
    /// Little-endian packed 0xXXRRGGBB pixels (GRPH_ARGB8888).
    Xrgb8888,
    /// Little-endian packed 0xAARRGGBB pixels (GRPH_ARGB8888).
    Argb8888,
    /// Little-endian packed 0xXXBBGGRR pixels (GRPH_ABGR8888).
    Xbgr8888,
    /// Little-endian packed 0xAABBGGRR pixels (GRPH_ABGR8888).
    Abgr8888,
    /// 2:10:10:10 x:R:G:B, little-endian (GRPH_ARGB2101010).
    Xrgb2101010,
    /// 2:10:10:10 A:R:G:B (GRPH_ARGB2101010).
    Argb2101010,
    /// 2:10:10:10 x:B:G:R (GRPH_ABGR2101010).
    Xbgr2101010,
    /// 2:10:10:10 A:B:G:R (GRPH_ABGR2101010).
    Abgr2101010,
    /// 5:6:5 R:G:B, little-endian 16-bit (GRPH_RGB565).
    Rgb565,
    /// 16:16:16:16 half-float x:R:G:B (GRPH_ARGB16161616F).
    Xrgb16161616f,
    /// 16:16:16:16 half-float A:R:G:B (GRPH_ARGB16161616F).
    Argb16161616f,
    /// 16:16:16:16 half-float x:B:G:R (GRPH_ABGR16161616F).
    Xbgr16161616f,
    /// 16:16:16:16 half-float A:B:G:R (GRPH_ABGR16161616F).
    Abgr16161616f,
    /// 8-bit Y plane, then an interleaved 8-bit CbCr plane at half
    /// resolution (VIDEO_420_YCrCb).
    Nv12,
    /// NV12 with 10 bits in each MSB-aligned 16-bit sample
    /// (VIDEO_420_10bpc_YCrCb).
    P010,
}
impl SurfaceFormat {
    /// Every format (new ones appended, so an index stays stable).
    pub const ALL: [Self; 15] = [
        Self::Xrgb8888,
        Self::Argb8888,
        Self::Xbgr8888,
        Self::Abgr8888,
        Self::Xrgb2101010,
        Self::Argb2101010,
        Self::Xbgr2101010,
        Self::Abgr2101010,
        Self::Rgb565,
        Self::Xrgb16161616f,
        Self::Argb16161616f,
        Self::Xbgr16161616f,
        Self::Abgr16161616f,
        Self::Nv12,
        Self::P010,
    ];
    /// The DRM fourcc (drm_fourcc.h).
    pub const fn fourcc(self) -> u32 {
        let code = match self {
            Self::Xrgb8888 => *b"XR24",
            Self::Argb8888 => *b"AR24",
            Self::Xbgr8888 => *b"XB24",
            Self::Abgr8888 => *b"AB24",
            Self::Xrgb2101010 => *b"XR30",
            Self::Argb2101010 => *b"AR30",
            Self::Xbgr2101010 => *b"XB30",
            Self::Abgr2101010 => *b"AB30",
            Self::Rgb565 => *b"RG16",
            Self::Xrgb16161616f => *b"XR4H",
            Self::Argb16161616f => *b"AR4H",
            Self::Xbgr16161616f => *b"XB4H",
            Self::Abgr16161616f => *b"AB4H",
            Self::Nv12 => *b"NV12",
            Self::P010 => *b"P010",
        };
        u32::from_le_bytes(code)
    }
    /// The format of a DRM fourcc, if this path scans it out.
    pub fn from_fourcc(fourcc: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.fourcc() == fourcc)
    }
    /// Bytes per pixel: DML's 444_16, 444_32 or 444_64 source format; the
    /// luma plane's for the 4:2:0 formats.
    pub const fn bytes_per_pixel(self) -> u32 {
        match self {
            Self::Nv12 => 1,
            Self::Rgb565 | Self::P010 => 2,
            Self::Xrgb16161616f
            | Self::Argb16161616f
            | Self::Xbgr16161616f
            | Self::Abgr16161616f => 8,
            _ => 4,
        }
    }
    /// The 256-byte-aligned linear pitch of a `width`-pixel line, in bytes.
    pub const fn pitch_bytes(self, width: u32) -> u32 {
        (width * self.bytes_per_pixel()).div_ceil(256) * 256
    }
    /// A two-plane 4:2:0 format (DC's SURFACE_PIXEL_FORMAT_VIDEO_BEGIN and
    /// up): its chroma has its own address, pitch and viewport.
    pub const fn is_video(self) -> bool {
        matches!(self, Self::Nv12 | Self::P010)
    }
    /// SPL's pixel format class (translate_SPL_in_params_from_pipe_ctx):
    /// SPL_PIXEL_FORMAT_420BPP8 / 420BPP10 for the video formats.
    pub const fn spl_video(self) -> Option<spl::Video> {
        match self {
            Self::Nv12 => Some(spl::Video::Nv12),
            Self::P010 => Some(spl::Video::P010),
            _ => None,
        }
    }
    /// Bytes per chroma (CbCr pair) element of a 4:2:0 format; 0 for RGB.
    pub const fn chroma_bytes_per_pixel(self) -> u32 {
        match self {
            Self::Nv12 => 2,
            Self::P010 => 4,
            _ => 0,
        }
    }
    /// hubp2_program_pixel_format's DCSURF_SURFACE_PIXEL_FORMAT: 3 RGB565,
    /// 8 A*GB8888, 10 A*GB2101010, 24 A*GB16161616F (the crossbar swaps
    /// the BGR orders).
    pub(in crate::amdgpu_dcn401_otg) const fn hubp_pixel_format(self) -> u32 {
        match self {
            // VIDEO_420_YCrCb 64, VIDEO_420_10bpc_YCrCb 66.
            Self::Nv12 => 64,
            Self::P010 => 66,
            Self::Rgb565 => 3,
            Self::Xrgb8888 | Self::Argb8888 | Self::Xbgr8888 | Self::Abgr8888 => 8,
            Self::Xrgb2101010 | Self::Argb2101010 | Self::Xbgr2101010 | Self::Abgr2101010 => 10,
            _ => 24,
        }
    }
    /// The DC ABGR surface formats, whose red and blue come in swapped.
    const fn abgr(self) -> bool {
        matches!(
            self,
            Self::Xbgr8888
                | Self::Abgr8888
                | Self::Xbgr2101010
                | Self::Abgr2101010
                | Self::Xbgr16161616f
                | Self::Abgr16161616f
        )
    }
    /// HUBPRET_CONTROL CROSSBAR_SRC_CB_B and CROSSBAR_SRC_CR_R
    /// (hubp2_program_pixel_format): blue from 2 and red from 3, swapped
    /// for the ABGR formats.
    pub(in crate::amdgpu_dcn401_otg) const fn crossbar(self) -> u32 {
        let (blue, red) = if self.abgr() { (3, 2) } else { (2, 3) };
        blue << 20 | red << 22
    }
    /// dpp401_dpp_setup's CNVC_SURFACE_PIXEL_FORMAT: as the HUBP's, except
    /// ABGR16161616F is 25 (Linux programs both its HUBP crossbar swap and
    /// this).
    pub(in crate::amdgpu_dcn401_otg) const fn cnvc_pixel_format(self) -> u32 {
        match self {
            Self::Xbgr16161616f | Self::Abgr16161616f => 25,
            _ => self.hubp_pixel_format(),
        }
    }
    /// dpp401_dpp_setup's FORMAT_CONTROL ALPHA_EN: off only for RGB565,
    /// which carries no alpha.
    pub(in crate::amdgpu_dcn401_otg) const fn cnvc_alpha(self) -> bool {
        !matches!(self, Self::Rgb565)
    }
    /// Per-pixel premultiplied alpha, as
    /// amdgpu_dm_plane_fill_blending_from_plane_state sets it for the
    /// primary plane's default "pixel blend mode" (Pre-multiplied): only its
    /// alpha_formats list, which (as in Linux) has ARGB16161616F but not
    /// ABGR16161616F. Every X format, and these otherwise, blends opaque
    /// (MPCC global alpha 0xff).
    pub const fn per_pixel_alpha(self) -> bool {
        matches!(
            self,
            Self::Argb8888
                | Self::Abgr8888
                | Self::Argb2101010
                | Self::Abgr2101010
                | Self::Argb16161616f
        )
    }
}
pub use crate::amdgpu_dm_modifiers::{DccBlock, Swizzle, Tiling};

/// A YCbCr plane's color space as amdgpu_dm's fill_plane_color_attributes
/// derives it from "COLOR_ENCODING" and "COLOR_RANGE" (DC's
/// COLOR_SPACE_YCBCR601/709 and 2020_YCBCR, full or limited). RGB planes
/// stay sRGB: their input CSC is bypassed whatever this says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum YuvColor {
    Bt601,
    Bt601Limited,
    Bt709,
    /// amdgpu_dm_plane_init's default (BT.709, limited range).
    #[default]
    Bt709Limited,
    Bt2020,
    Bt2020Limited,
}
impl YuvColor {
    /// fill_plane_color_attributes for DRM_COLOR_YCBCR_BT601/709/2020
    /// (0, 1, 2) and DRM_COLOR_YCBCR_LIMITED/FULL_RANGE (0, 1); None for
    /// another encoding (-EINVAL).
    pub const fn from_props(encoding: u8, range: u8) -> Option<Self> {
        let full = range == 1;
        Some(match (encoding, full) {
            (0, true) => Self::Bt601,
            (0, false) => Self::Bt601Limited,
            (1, true) => Self::Bt709,
            (1, false) => Self::Bt709Limited,
            (2, true) => Self::Bt2020,
            (2, false) => Self::Bt2020Limited,
            _ => return None,
        })
    }
    /// The color space's `dpp_input_csc_matrix` entry (dc/inc/hw/dpp.h):
    /// the 3x4 YCbCr-to-RGB matrix in S2.13, row by row, which
    /// dpp3_program_post_csc loads into CM_POST_CSC_C11_C12..C33_C34.
    pub const fn matrix(self) -> [u16; 12] {
        match self {
            Self::Bt601 => [
                0x2cdd, 0x2000, 0, 0xe991, 0xe926, 0x2000, 0xf4fd, 0x10ef, 0, 0x2000, 0x38b4,
                0xe3a6,
            ],
            Self::Bt601Limited => [
                0x3353, 0x2568, 0, 0xe400, 0xe5dc, 0x2568, 0xf367, 0x1108, 0, 0x2568, 0x40de,
                0xdd3a,
            ],
            Self::Bt709 => [
                0x3265, 0x2000, 0, 0xe6ce, 0xf105, 0x2000, 0xfa01, 0xa7d, 0, 0x2000, 0x3b61, 0xe24f,
            ],
            Self::Bt709Limited => [
                0x39a6, 0x2568, 0, 0xe0d6, 0xeedd, 0x2568, 0xf925, 0x9a8, 0, 0x2568, 0x43ee, 0xdbb2,
            ],
            Self::Bt2020 => [
                0x2f30, 0x2000, 0, 0xe869, 0xedb7, 0x2000, 0xfabc, 0xbc6, 0, 0x2000, 0x3c34, 0xe1e6,
            ],
            Self::Bt2020Limited => [
                0x35b9, 0x2543, 0, 0xe2b2, 0xeb2f, 0x2543, 0xfa01, 0x0b1f, 0, 0x2543, 0x4489,
                0xdb42,
            ],
        }
    }
}

/// What a plane's framebuffer is beyond its format: its modifier's GFX12
/// swizzle and DCC (amdgpu_dm_plane_fill_gfx12_attrs_from_modifiers), and
/// a YCbCr plane's color space.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlaneSurface {
    pub tiling: Tiling,
    pub color: YuvColor,
}
impl PlaneSurface {
    /// A linear RGB (or default-colored YCbCr) surface.
    pub const LINEAR: Self = Self {
        tiling: Tiling::LINEAR,
        color: YuvColor::Bt709Limited,
    };
}

/// Where each plane of a surface lies in its allocation, as
/// amdgpu_display_verify_plane sizes a framebuffer's planes: a pitch of
/// whole swizzle blocks covering the width, whole block rows covering the
/// height; a 4:2:0 surface's chroma plane (half width and height,
/// rounded up) follows the luma at a block-aligned offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceBytes {
    pub pitch_bytes: u32,
    /// The chroma plane's offset from the surface address and its pitch in
    /// bytes; none for RGB.
    pub chroma: Option<(u64, u32)>,
    /// The whole surface, both planes.
    pub bytes: u64,
}

/// How a plane blends over what lies below it in the MPCC tree, as
/// amdgpu_dm_plane_fill_blending_from_plane_state derives it from the DRM
/// plane's "pixel blend mode" and "alpha" (dcn401_update_mpcc_sequence
/// programs it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blend {
    /// Per-pixel alpha: an A format with blend mode Pre-multiplied or
    /// Coverage. Also the line buffer's ALPHA_EN.
    pub per_pixel_alpha: bool,
    /// Pre-multiplied (not Coverage) per-pixel alpha.
    pub premultiplied: bool,
    /// The plane alpha below 0xffff, as amdgpu_dm passes it to an 8-bit
    /// MPCC_GLOBAL_ALPHA (`alpha >> 8`); none while opaque.
    pub global_alpha: Option<u8>,
}
impl Blend {
    /// The default plane state (blend mode Pre-multiplied, alpha opaque).
    pub const fn default_for(format: SurfaceFormat) -> Self {
        Self {
            per_pixel_alpha: format.per_pixel_alpha(),
            premultiplied: true,
            global_alpha: None,
        }
    }
}
/// Where a plane's surface shows, as amdgpu_dm_plane_fill_dc_scaling_info
/// hands it to DC: its source rectangle in the surface and its destination
/// on the stream (DRM's SRC_* and CRTC_*, the clip being the destination),
/// with the stream it is scanned out on, and the plane's rotation and
/// blending. SPL turns it into each pipe's viewport, recout and scaler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaneLayout {
    pub src: spl::Rect,
    pub dst: spl::Rect,
    /// The stream's addressable size.
    pub stream_width: u32,
    pub stream_height: u32,
    /// The stream leaves as YCbCr 4:2:0: an ODM right half's OPP takes one
    /// extra left-edge pixel (resource_get_odm_slice_src_rect).
    pub ycbcr420: bool,
    /// DRM's ROTATE_0/90/180/270 as DC's ROTATION_ANGLE. A 90/270 plane
    /// is scanned vertically, which DML refuses for a linear surface
    /// (SourceFormatPixelAndScanSupport).
    pub rotation: spl::Rotation,
    pub blend: Blend,
    /// An overlay below the primary (its normalized zpos lower than the
    /// primary's): it blends under the primary instead of above it.
    pub underlay: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceRequest {
    pub pipe: u8,
    pub width: u32,
    pub height: u32,
    pub format: SurfaceFormat,
    /// ODM: the stream's further segment pipes (`Request::odm`), whose
    /// HUBPs fetch the following segments of the same surface (and whose
    /// DPP/MPCC/DET follow them). Their own timing, surface slot and memory
    /// stay unused.
    pub odm: SplitPipes,
    /// MPC combine on a stream in ODM bypass: the plane's further pipes,
    /// each fetching the next slice of its recout (resource_get_mpc_slice_
    /// index) and blended below the one before in the stream's MPCC tree.
    /// Never with `odm`; their timing, surface slot and memory stay unused.
    pub mpc: SplitPipes,
    /// The plane's placement; `None` is the whole surface unscaled on a
    /// stream of its own size, blended as `Blend::default_for` its format.
    pub plane: Option<PlaneLayout>,
    /// The framebuffer's tiling, DCC and YCbCr color space.
    pub surface: PlaneSurface,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceApplied {
    pub request: SurfaceRequest,
    /// GPU framebuffer address, never a CPU BAR or translated physical address.
    pub address: u64,
    /// The luma (or RGB) pitch HUBP fetches with: the staged buffers'
    /// (`SurfaceRequest::bytes`), or a client framebuffer's scanned out in
    /// place (fb->pitches[0], as amdgpu_dm_plane_fill_plane_buffer_attributes
    /// hands DC its surface_pitch).
    pub pitch_bytes: u32,
    /// The staged buffers' size: visible rows including pitch padding (the
    /// reservation is page-rounded). A client framebuffer's never.
    pub bytes: u64,
    /// A 4:2:0 surface's chroma plane: its offset from `address` and its
    /// pitch in bytes (the staged layout, or a client framebuffer's
    /// offsets[1] - offsets[0] and pitches[1]); none for RGB.
    pub chroma: Option<(u64, u32)>,
}
impl SurfaceRequest {
    fn geometry(self) -> Result<(u32, u64), Error> {
        if self.pipe >= 4
            || self.width == 0
            || self.height == 0
            || self.width > 0x3fff
            || self.height > 0x3fff
            || !self.odm.valid_with(self.pipe)
            || !self.mpc.valid_with(self.pipe)
            || (self.odm.is_some() && (self.mpc.is_some() || self.width % 2 != 0))
        {
            return Err(Error::Invalid);
        }
        if let Some(p) = self.plane {
            let (s, d) = (p.src, p.dst);
            let within = |start: i32, len: i32, size: u32| {
                start >= 0 && len > 0 && start as u64 + len as u64 <= u64::from(size)
            };
            if !within(s.x, s.width, self.width)
                || !within(s.y, s.height, self.height)
                || d.width <= 0
                || d.height <= 0
                || p.stream_width == 0
                || p.stream_height == 0
                || p.stream_width > 0x3fff
                || p.stream_height > 0x3fff
                || self.odm.is_some() && p.stream_width % 2 != 0
                || (p.blend.per_pixel_alpha && !self.format.cnvc_alpha())
                // Some pixel must land on the stream.
                || d.x >= p.stream_width as i32
                || d.y >= p.stream_height as i32
                || i64::from(d.x) + i64::from(d.width) <= 0
                || i64::from(d.y) + i64::from(d.height) <= 0
            {
                return Err(Error::Invalid);
            }
            // DML's SourceFormatPixelAndScanSupport: no linear surface
            // scanned vertically.
            if p.rotation.orthogonal() && self.surface.tiling.swizzle == Swizzle::Linear {
                return Err(Error::Unsupported);
            }
            // Every pipe's SPL must succeed (resource_build_scaling_params).
            if self.scalers().any(|(_, scaler)| !scaler.ok) {
                return Err(Error::Unsupported);
            }
        }
        // DCC on a format hubbub401_get_dcc_compression_cap refuses.
        if self.surface.tiling.dcc.is_some()
            && !crate::amdgpu_dm_modifiers::dcc_capable(self.format.fourcc(), self.width)
        {
            return Err(Error::Unsupported);
        }
        let b = self.bytes();
        Ok((b.pitch_bytes, b.bytes))
    }
    /// The surface's planes in memory: linear rows 256-byte aligned (one
    /// LINEAR block), a tiled surface in whole swizzle blocks.
    pub fn bytes(self) -> SurfaceBytes {
        let swizzle = self.surface.tiling.swizzle;
        let plane = |width: u32, height: u32, cpp: u32| {
            let (block_width, block_height) = swizzle.block(cpp);
            let block_pitch = block_width * cpp;
            let pitch = (width * cpp).div_ceil(block_pitch) * block_pitch;
            let bytes = u64::from(pitch / block_pitch)
                * (1u64 << swizzle.block_log2())
                * u64::from(height.div_ceil(block_height));
            (pitch, bytes)
        };
        let (pitch_bytes, luma) = plane(self.width, self.height, self.format.bytes_per_pixel());
        if !self.format.is_video() {
            return SurfaceBytes {
                pitch_bytes,
                chroma: None,
                bytes: luma,
            };
        }
        let (chroma_pitch, chroma) = plane(
            self.width.div_ceil(2),
            self.height.div_ceil(2),
            self.format.chroma_bytes_per_pixel(),
        );
        // The chroma plane starts on a block (and at least a 4 KiB page).
        let align = 1u64 << swizzle.block_log2().max(12);
        let offset = luma.div_ceil(align) * align;
        SurfaceBytes {
            pitch_bytes,
            chroma: Some((offset, chroma_pitch)),
            bytes: offset + chroma,
        }
    }
}
impl SurfaceRequest {
    /// A 4:2:0 surface's chroma plane: its offset from the surface address
    /// and its pitch in bytes.
    pub fn chroma(self) -> Option<(u64, u32)> {
        self.bytes().chroma
    }
    /// The effective layout: the request's, or the whole surface unscaled.
    pub fn layout(self) -> PlaneLayout {
        self.plane.unwrap_or(PlaneLayout {
            src: spl::Rect::new(0, 0, self.width as i32, self.height as i32),
            dst: spl::Rect::new(0, 0, self.width as i32, self.height as i32),
            stream_width: self.width,
            stream_height: self.height,
            ycbcr420: false,
            rotation: spl::Rotation::R0,
            blend: Blend::default_for(self.format),
            underlay: false,
        })
    }
    /// Whether staging would take this request: its surface and layout
    /// are well formed and every ODM segment's SPL succeeds
    /// (resource_build_scaling_params). `Invalid` or `Unsupported` as
    /// staging would refuse it; nothing is touched.
    pub fn check(self) -> Result<(), Error> {
        self.geometry().map(|_| ())
    }
    /// Whether this is the unscaled full-frame plane of its stream.
    pub fn full_frame(self) -> bool {
        let l = self.layout();
        l.src == spl::Rect::new(0, 0, self.width as i32, self.height as i32)
            && l.dst == spl::Rect::new(0, 0, l.stream_width as i32, l.stream_height as i32)
            && l.stream_width == self.width
            && l.stream_height == self.height
            && l.rotation == spl::Rotation::R0
    }
    /// Every pipe the surface's fetch occupies, the request's own first:
    /// each with the ODM segment its OPP output carries and its MPC slice
    /// (ODM segments in order, or MPC slices on the one segment).
    pub(in crate::amdgpu_dcn401_otg) fn slices(
        self,
    ) -> impl Iterator<Item = (u8, u32, u32)> + Clone {
        let odm = self
            .odm
            .iter()
            .enumerate()
            .map(|(k, p)| (p, k as u32 + 1, 0));
        let mpc = self
            .mpc
            .iter()
            .enumerate()
            .map(|(k, p)| (p, 0, k as u32 + 1));
        core::iter::once((self.pipe, 0, 0)).chain(odm).chain(mpc)
    }
    /// Each fetching pipe and SPL's input for it, the request's own pipe
    /// first; the whole stream on that pipe without ODM.
    /// resource_get_odm_slice_src_rect: the segments of
    /// resource_get_odm_slice_dst_width, each 4:2:0 segment after the first
    /// one pixel wider to the left; an MPC slice's index and count.
    pub(in crate::amdgpu_dcn401_otg) fn spl_inputs(
        self,
    ) -> impl Iterator<Item = (u8, spl::Input)> + Clone {
        let l = self.layout();
        let (w, h) = (l.stream_width as i32, l.stream_height as i32);
        let edge = i32::from(l.ycbcr420);
        let mpc_count = self.mpc.count() as i32;
        self.slices()
            .zip(self.segments())
            .map(move |((p, segment, slice), (_, x, width))| {
                let edge = if segment > 0 { edge } else { 0 };
                let odm_slice = spl::Rect::new(x as i32 - edge, 0, width as i32 + edge, h);
                let input = spl::Input {
                    src: l.src,
                    dst: l.dst,
                    clip: l.dst,
                    stream_width: w,
                    stream_height: h,
                    odm_slice,
                    mpc_slice: (slice as i32, mpc_count),
                    rotation: l.rotation,
                    horizontal_mirror: false,
                    alpha: l.blend.per_pixel_alpha,
                    video: self.format.spl_video(),
                };
                (p, input)
            })
    }
    /// Each segment's pipe and spl_calculate_scaler_params' result. A
    /// request without a layout is the whole surface unscaled: each segment
    /// bypasses the scaler with its own columns (`spl::Scaler::unity`), as
    /// SPL computes it for any surface of at least its 12-pixel minimum
    /// viewport and no 4:2:0 ODM.
    pub(in crate::amdgpu_dcn401_otg) fn scalers(
        self,
    ) -> impl Iterator<Item = (u8, spl::Scaler)> + Clone {
        let height = self.height as i32;
        // A 4:2:0 surface always scales its chroma: SPL even for the whole
        // frame.
        let laid_out = self.plane.is_some() || self.format.is_video();
        let mpc_count = self.mpc.count() as i32;
        self.spl_inputs()
            .zip(self.segments())
            .map(move |((p, input), (_, x, width))| {
                let scaler = if laid_out {
                    spl::calculate(&input)
                } else if mpc_count > 1 {
                    // The MPC slice of the whole unscaled surface.
                    let r =
                        spl::mpc_slice(spl::Rect::new(0, 0, width as i32, height), input.mpc_slice);
                    spl::Scaler::unity_at(r.x, r.x, r.width, height)
                } else {
                    spl::Scaler::unity(x as i32, width as i32, height)
                };
                (p, scaler)
            })
    }
    /// dml21_get_pipe_mcache_config for pipe `p` of the request: the x and
    /// width of the pipe's own SPL luma viewport, and of its chroma
    /// viewport for a 4:2:0 surface (scl_data.viewport and viewport_c, also
    /// when rotated). `None` for a pipe the request does not fetch on.
    pub fn mcache_viewports(self, p: u8) -> Option<((u32, u32), Option<(u32, u32)>)> {
        let (_, scaler) = self.scalers().find(|&(q, _)| q == p)?;
        let span = |r: spl::Rect| (r.x.max(0) as u32, r.width.max(0) as u32);
        let chroma = self.format.is_video().then(|| span(scaler.viewport_c));
        Some((span(scaler.viewport), chroma))
    }
    /// resource_build_scaling_params for pipe `p` of the request: whether
    /// SPL can scale the plane on that pipe's slice (`scalers`); true for
    /// a pipe the request does not fetch on.
    pub fn scales_on(self, p: u8) -> bool {
        self.scalers()
            .find(|&(q, _)| q == p)
            .is_none_or(|(_, scaler)| scaler.ok)
    }
    /// Each fetching pipe with its ODM segment's first stream column and
    /// width (resource_get_odm_slice_dst_rect: the line over the segment
    /// count, in whole pixel pairs for 4:2:0, the last segment the rest),
    /// the request's own pipe first; the whole stream on every pipe
    /// without ODM (its MPC slices share the one segment).
    pub(in crate::amdgpu_dcn401_otg) fn segments(
        self,
    ) -> impl Iterator<Item = (u8, u32, u32)> + Clone {
        let l = self.layout();
        let w = l.stream_width;
        let count = self.odm.count();
        let first = w / count;
        let first = first + (first & 1 & u32::from(l.ycbcr420 && count > 1));
        self.slices().map(move |(p, segment, _)| {
            if segment + 1 == count {
                (p, segment * first, w - first * (count - 1))
            } else {
                (p, segment * first, first)
            }
        })
    }
    /// The plane as DC hands it to DML21 after SPL
    /// (populate_dml21_plane_config_from_plane_state): the surface, the
    /// whole-plane viewport, ratios and taps SPL computes on the whole
    /// stream (`dml::Plane::full` for the unscaled full-frame plane).
    pub fn dml_plane(self) -> crate::amdgpu_dcn401_dml::Plane {
        let bpp = self.format.bytes_per_pixel();

        let l = self.layout();
        let (w, h) = (l.stream_width as i32, l.stream_height as i32);
        let s = if self.plane.is_some() || self.format.is_video() {
            spl::calculate(&spl::Input {
                src: l.src,
                dst: l.dst,
                clip: l.dst,
                stream_width: w,
                stream_height: h,
                odm_slice: spl::Rect::new(0, 0, w, h),
                mpc_slice: (0, 1),
                rotation: l.rotation,
                horizontal_mirror: false,
                alpha: l.blend.per_pixel_alpha,
                video: self.format.spl_video(),
            })
        } else {
            spl::Scaler::unity(0, w, h)
        };
        let [v_taps, h_taps, v_taps_c, h_taps_c] = s.dc_taps();
        use crate::amdgpu_dcn401_dml::{Chroma, Plane, Source, Swizzle as DmlSwizzle};
        let bytes = self.bytes();
        let pitch = bytes.pitch_bytes / bpp;
        // populate_dml21_surface_config_from_plane_state: the plane's
        // source format, the DC_ADDR3 swizzle, DCC, the scan direction and
        // (4:2:0) plane 1: half the surface (DC's chroma_size), its pitch,
        // and SPL's chroma viewport, ratios and taps.
        let source = match self.format {
            SurfaceFormat::Nv12 => Source::Yuv420_8,
            SurfaceFormat::P010 => Source::Yuv420_10,
            _ => Source::Rgb,
        };
        let swizzle = match self.surface.tiling.swizzle {
            Swizzle::Linear => DmlSwizzle::Linear,
            Swizzle::S256B2D => DmlSwizzle::S256B2D,
            Swizzle::S4K2D => DmlSwizzle::S4K2D,
            Swizzle::S64K2D => DmlSwizzle::S64K2D,
            Swizzle::S256K2D => DmlSwizzle::S256K2D,
        };
        let chroma = bytes.chroma.map(|(_, pitch_c)| Chroma {
            surface_width: Plane::extent(self.width / 2),
            surface_height: Plane::extent(self.height / 2),
            pitch: Plane::extent(pitch_c / self.format.chroma_bytes_per_pixel()),
            viewport_width: Plane::extent(s.viewport_c.width as u32),
            viewport_height: Plane::extent(s.viewport_c.height as u32),
            h_ratio: s.ratios[2] >> 5,
            v_ratio: s.ratios[3] >> 5,
            h_taps: Plane::count(h_taps_c),
            v_taps: Plane::count(v_taps_c),
        });
        Plane {
            source,
            swizzle,
            dcc: self.surface.tiling.dcc.is_some(),
            vertical_scan: l.rotation.orthogonal(),
            chroma,
            surface_width: Plane::extent(self.width),
            surface_height: Plane::extent(self.height),
            pitch: Plane::extent(pitch),
            bytes_per_pixel: Plane::count(bpp),
            viewport_width: Plane::extent(s.viewport.width as u32),
            viewport_height: Plane::extent(s.viewport.height as u32),
            h_ratio: s.ratios[0] >> 5,
            v_ratio: s.ratios[1] >> 5,
            h_taps: Plane::count(h_taps),
            v_taps: Plane::count(v_taps),
        }
    }
    /// Whether `other` fits the same buffers: the same pipe(s), size and
    /// format (the placement may differ).
    pub(in crate::amdgpu_dcn401_otg) fn same_allocation(self, other: Self) -> bool {
        (
            self.pipe,
            self.width,
            self.height,
            self.format,
            self.odm,
            self.mpc,
            self.bytes(),
        ) == (
            other.pipe,
            other.width,
            other.height,
            other.format,
            other.odm,
            other.mpc,
            other.bytes(),
        )
    }
    /// Every pipe the surface's fetch occupies, by bit.
    pub(in crate::amdgpu_dcn401_otg) fn pipe_mask(self) -> u8 {
        self.segments().fold(0, |m, (p, _, _)| m | bit(p))
    }
}
impl SurfaceApplied {
    /// The staged buffers' layout for `request` at `address`.
    pub fn staged(request: SurfaceRequest, address: u64, pitch_bytes: u32, bytes: u64) -> Self {
        Self {
            request,
            address,
            pitch_bytes,
            bytes,
            chroma: request.chroma(),
        }
    }
    /// The same plane fetching the staged buffer at `address` (a back
    /// buffer or the front reservation): the staged pitch and chroma.
    pub(in crate::amdgpu_dcn401_otg) fn at_staged(self, address: u64) -> Self {
        Self {
            address,
            pitch_bytes: self.request.bytes().pitch_bytes,
            chroma: self.request.chroma(),
            ..self
        }
    }
    /// The byte offset of `count` packed 32-bit words written into row `y`
    /// from pixel `x`: they start on a word and end within the row's pixels
    /// rounded up to whole words (inside the 256-byte-aligned pitch).
    pub(in crate::amdgpu_dcn401_otg) fn row_words(
        self,
        x: u32,
        y: u32,
        count: usize,
    ) -> Result<u64, Error> {
        let bpp = self.request.format.bytes_per_pixel();
        let count = u32::try_from(count).map_err(|_| Error::Invalid)?;
        let row = (self.request.width * bpp).div_ceil(4);
        let first = u64::from(x) * u64::from(bpp);
        if count == 0
            || y >= self.request.height
            || first % 4 != 0
            || first / 4 + u64::from(count) > u64::from(row)
        {
            return Err(Error::Invalid);
        }
        // The staged buffers' rows, whichever buffer the plane fetches.
        Ok(u64::from(y) * u64::from(self.request.bytes().pitch_bytes) + first)
    }
    /// The chroma plane's address (DCSURF_PRIMARY_SURFACE_ADDRESS_C) for a
    /// surface at `address`; none for RGB.
    pub fn chroma_address(self, address: u64) -> Option<u64> {
        self.chroma.map(|(offset, _)| address + offset)
    }
    /// One segment's HUBP surface registers, in hubp401_program_surface_config
    /// and hubp401_program_surface_flip_and_addr's terms: DCSURF_SURFACE_CONTROL
    /// (no TMZ; PRIMARY/SECONDARY_SURFACE_DCC_EN as hubp401_dcc_control sets
    /// them from the modifier), hubp401_program_tiling's SW_MODE (the GFX12
    /// swizzle; DIM_TYPE stays at the native 2D), hubp401_program_size's
    /// PITCH (and a 4:2:0 surface's PITCH_C) in pixels less one,
    /// hubp2_program_rotation and hubp2_program_pixel_format's rotation,
    /// format and crossbar, SPL's luma and chroma viewports for that segment
    /// (hubp401_set_viewport), then the addresses: a 4:2:0 surface's chroma
    /// first, high halves before low.
    fn registers(self, scaler: &spl::Scaler) -> alloc::vec::Vec<(u64, u32, u32)> {
        let format = self.request.format;
        let tiling = self.request.surface.tiling;
        let rotation = self.request.layout().rotation as u32;
        let [d, s, sd, ss, dc, sc, sdc, ssc] = crate::amdgpu_dcn401_dscl::viewport(scaler);
        let dcc = if tiling.dcc.is_some() { 0x202 } else { 0 };
        // PRIMARY_SURFACE_TMZ, and PRIMARY_SURFACE_TMZ_C for a 4:2:0
        // (VIDEO_PROGRESSIVE) address; both DCC enables.
        let tmz = if format.is_video() { 0x11 } else { 1 };
        let mut out = alloc::vec![
            (0x612, 0x202 | tmz, dcc),
            (0x5e7, 7, tiling.swizzle as u32),
            (
                0x607,
                0xffff,
                self.pitch_bytes / format.bytes_per_pixel() - 1,
            ),
        ];
        if let Some((_, pitch_c)) = self.chroma {
            out.push((0x608, 0xffff, pitch_c / format.chroma_bytes_per_pixel() - 1));
        }
        out.extend([
            // ROTATION_ANGLE; no mirror or alpha plane.
            (0x5e5, 0xf7f, format.hubp_pixel_format() | rotation << 8),
            (0x66d, 0xf00000, format.crossbar()),
            d,
            s,
            sd,
            ss,
            dc,
            sc,
            sdc,
            ssc,
            (0x609, 0xf, 0),    // VMID0, physical FB aperture still needs setup
            (FLIP, 0x130f2, 0), // normal, non-stereo, no skipped vupdates
            (FLIP2, 0x700, 0),  // no GSL or triple buffering
        ]);
        if let Some(c) = self.chroma_address(self.address) {
            out.extend([
                (0x60d, 0xffff, (c >> 32) as u32),
                (0x60c, u32::MAX, c as u32),
            ]);
        }
        out.extend([
            (0x60b, 0xffff, (self.address >> 32) as u32),
            // Low address publishes the flip: it must be the last surface write.
            (0x60a, u32::MAX, self.address as u32),
        ]);
        out
    }
}

#[derive(Debug)]
struct Surface {
    /// The front buffer: the one `applied` and every report name.
    memory: Reservation,
    applied: SurfaceApplied,
    /// Optional second buffer of the same geometry, swapped in by a flip.
    back: Option<Reservation>,
    /// 64x64 ARGB cursor image, allocated on first use.
    cursor: Option<Reservation>,
}
/// The staged surface of each pipe, and the parked ones a geometry change
/// left behind.
#[derive(Debug)]
pub(in super::super) struct Surfaces([Option<Surface>; 4], alloc::vec::Vec<Surface>);
impl Surfaces {
    pub(in super::super) fn new() -> Self {
        Self(core::array::from_fn(|_| None), alloc::vec::Vec::new())
    }
    pub(in super::super) async fn prepare<I: Io>(
        &mut self,
        engine: &mut Engine<I>,
        pool: &Pool,
        request: SurfaceRequest,
    ) -> Result<SurfaceApplied, Error> {
        let (pitch_bytes, bytes) = request.geometry()?;
        // Every fetching pipe is a pipe index of this pool (fused slots past
        // `count` have no blocks).
        let count = engine.layout.pool.count();
        if request.segments().any(|(p, _, _)| p >= count) {
            return Err(Error::Invalid);
        }
        let slot = usize::from(request.pipe);
        // Restaging a torn-down pipe (a replug) is allowed only right after
        // plane retirement (and the HUBP power-up that follows it in a
        // modeset), with fresh evidence that no HUBP fetches.
        let restage = self.0[slot].is_some();
        if restage {
            if !matches!(
                engine.status.state,
                State::PlanesRetired | State::HubpPowerChanged
            ) {
                return Err(Error::Busy);
            }
            engine.fetchers_stopped()?;
        }
        if !engine.status.state.reusable() {
            return Err(Error::Busy);
        }
        for (p, _, _) in request.segments() {
            engine.surface_preflight(p, restage)?;
        }
        // The same geometry reuses the buffers: a console write still in
        // flight to the old scanout can only land on this same surface. A new
        // geometry parks them instead until explicit CPU/hardware retirement
        // permits release_surfaces to return them to the pool. Otherwise a
        // later request for a parked geometry on this pipe reuses that
        // surface. Mode switches between the sink's few offered modes then
        // retain at most one surface (front, back, cursor) per geometry.
        if let Some(old) = self.0[slot].take() {
            if old.applied.request.same_allocation(request) {
                self.0[slot] = Some(old);
            } else {
                self.1.push(old);
            }
        }
        if self.0[slot].is_none() {
            if let Some(i) = self
                .1
                .iter()
                .position(|p| p.applied.request.same_allocation(request))
            {
                self.0[slot] = Some(self.1.swap_remove(i));
            }
        }
        let (memory, back, cursor) = match self.0[slot].take() {
            Some(old) => (old.memory, old.back, old.cursor),
            None => (
                pool.reserve(bytes).map_err(|_| Error::Allocation)?,
                None,
                None,
            ),
        };
        if memory.address() == 0
            || memory
                .address()
                .checked_add(memory.size())
                .is_none_or(|end| end > 1 << 48)
        {
            return Err(Error::Invalid);
        }
        let applied = SurfaceApplied::staged(request, memory.address(), pitch_bytes, bytes);
        self.0[slot] = Some(Surface {
            memory,
            applied,
            back,
            cursor,
        });
        engine.status.state = State::PreparingSurface(request.pipe);
        engine.status.surfaces[slot] = None;
        let result = self.initialize(engine, slot, restage).await;
        match result {
            Ok(()) => {
                engine.status.surfaces[slot] = Some(applied);
                engine.status.state = State::SurfacePrepared;
                Ok(applied)
            }
            Err(e) => {
                engine.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    async fn initialize<I: Io>(
        &mut self,
        engine: &mut Engine<I>,
        slot: usize,
        restage: bool,
    ) -> Result<(), Error> {
        let surface = self.0[slot].as_mut().ok_or(Error::Invalid)?;
        let map = surface.memory.mapping();
        // Clear padding too, with bounded CPU work and fresh authority per chunk.
        for start in (0..map.len).step_by(65536) {
            let end = (start + 65536).min(map.len);
            engine.access(|_| {
                for offset in (start..end).step_by(4) {
                    // SAFETY: live authority and an owned, permanent VRAM mapping.
                    unsafe { map.write32(offset, 0) };
                }
                Ok(())
            })?;
            if end < map.len {
                narf_scheduler::yield_now().await;
            }
        }
        engine.flush_surface_writes()?;
        // Recheck after cooperative clearing, before any surface register changes.
        for (p, _, _) in surface.applied.request.segments() {
            engine.surface_preflight(p, restage)?;
        }
        surface.memory.publish();
        engine.program_surface(surface.applied).await
    }
    pub(in super::super) fn upload<I: Io>(
        &mut self,
        engine: &mut Engine<I>,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), Error> {
        let surface = self
            .0
            .get(usize::from(pipe))
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        let a = surface.applied;
        let start = a.row_words(x, y, pixels.len())?;
        if !engine.status.state.reusable() || engine.status.surfaces[usize::from(pipe)] != Some(a) {
            return Err(Error::Busy);
        }
        engine.hubp_tree_stopped(Some(pipe))?;
        engine.verify_surface(a)?;
        let map = surface.memory.mapping();
        engine.status.state = State::PreparingSurface(pipe);
        let result = engine
            .access(|_| {
                for (index, &pixel) in pixels.iter().enumerate() {
                    // SAFETY: checked row bounds within the retained VRAM allocation.
                    unsafe { map.write32(start + index as u64 * 4, pixel) };
                }
                Ok(())
            })
            .and_then(|()| engine.flush_surface_writes())
            .and_then(|()| engine.hubp_tree_stopped(Some(pipe)))
            .and_then(|()| engine.verify_surface(a));
        if let Err(e) = result {
            engine.status.surfaces[usize::from(pipe)] = None;
            engine.status.state = State::Failed(e);
            return Err(e);
        }
        engine.status.state = State::SurfacePrepared;
        Ok(())
    }
}
impl<I: Io> Engine<I> {
    /// The pipes `pipe`'s staged surface fetches on: itself, then its ODM
    /// pipes or MPC slices' pipes.
    pub(in crate::amdgpu_dcn401_otg) fn fetch_pipes(&self, pipe: u8) -> impl Iterator<Item = u8> {
        let (odm, mpc) = self
            .status
            .surfaces
            .get(usize::from(pipe))
            .copied()
            .flatten()
            .map_or((SplitPipes::NONE, SplitPipes::NONE), |a| {
                (a.request.odm, a.request.mpc)
            });
        core::iter::once(pipe).chain(odm).chain(mpc)
    }
    /// A restaged pipe may still show its previous staged address pending:
    /// those buffers stay owned until a separate, stricter release proof.
    fn surface_preflight(&mut self, pipe: u8, restage: bool) -> Result<(), Error> {
        if restage {
            self.hubp_tree_stopped(Some(pipe))?;
        } else {
            // The display's planes already staged (an overlay's primary)
            // may hold their own pending addresses; nothing else may.
            self.hubp_tree_stopped_mask(self.staged_planes())?;
        }
        if !self.hubp_powered(pipe)? {
            return Err(Error::Busy);
        }
        let l = self.layout;
        if self.read(l.hubp(pipe, HUBP_CONTROL))? & 0x1007 != 3
            || self.read(l.hubp(pipe, 0x5e7))? & 0x180 != 0x80
            || self.read(l.nbio + 0x12d * 4)? != 0x7f000
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn flush_surface_writes(&mut self) -> Result<(), Error> {
        if self.read(self.layout.nbio + 0x12d * 4)? != 0x7f000 {
            return Err(Error::Busy);
        }
        // Native CPU HDP flush: WC stores, remapped HDP write, PCIe read drain.
        fence(Ordering::SeqCst);
        self.access(|io| {
            io.write(0x7f000, 0);
            Ok(())
        })?;
        self.read(self.layout.nbio + 0xc3 * 4)?;
        fence(Ordering::SeqCst);
        Ok(())
    }
    fn verify_surface(&mut self, surface: SurfaceApplied) -> Result<(), Error> {
        let l = self.layout;
        for (p, scaler) in surface.request.scalers() {
            if !self.hubp_powered(p)? {
                return Err(Error::Busy);
            }
            if self.read(l.hubp(p, 0x5e7))? & 0x180 != 0x80 {
                return Err(Error::Busy);
            }
            for (r, mask, value) in surface.registers(&scaler) {
                let at = l.hubp(p, r);
                if self.read(at)? & mask != value {
                    return Err(Error::Readback(at));
                }
            }
        }
        Ok(())
    }
    async fn program_surface(&mut self, surface: SurfaceApplied) -> Result<(), Error> {
        let l = self.layout;
        for (p, scaler) in surface.request.scalers() {
            self.update(l.hubp(p, HUBP_CLOCK), 1, 1)?;
            self.wait(l.hubp(p, HUBP_CONTROL), 0x1007, 3, 100_000)
                .await?;
            for (r, mask, value) in surface.registers(&scaler) {
                self.update(l.hubp(p, r), mask, value)?;
            }
            // Address writes may leave a pending flip until timing runs. That
            // is not an active fetch and must never be treated as flip
            // completion.
            self.wait(l.hubp(p, HUBP_CONTROL), 0x1007, 3, 100_000)
                .await?;
            self.update(l.hubp(p, HUBP_CLOCK), 1, 0)?;
        }
        self.hubp_tree_stopped_mask(surface.request.pipe_mask() | self.staged_planes())?;
        self.verify_surface(surface)
    }
}
impl Otg {
    /// Allocate, clear and stage a linear RGB framebuffer while fetch is blank.
    /// A staged address may remain pending; VM, bandwidth, DPP/MPC and output
    /// activation are separate prerequisites. Each pipe retains its allocation;
    /// after plane retirement the pipe may be restaged, reusing the buffers
    /// for the same geometry and parking them otherwise until explicit release.
    /// # Safety
    /// `pool` must exclusively own this GPU's correctly mapped VRAM. Exclude
    /// firmware/FAMS and concurrent display/HDP/clock/power writers. Retain all
    /// inherited resources and this owner on success, error and cancellation.
    pub async unsafe fn prepare_surface(
        &mut self,
        pool: &Pool,
        request: SurfaceRequest,
    ) -> Result<SurfaceApplied, Error> {
        self.1.prepare(&mut self.0, pool, request).await
    }
    /// Upload part of one visible row of a staged, stopped surface: `pixels`
    /// are the row's packed little-endian 32-bit words from pixel `x` (one
    /// word per pixel at 4 bytes per pixel). No raw CPU pointer escapes. The
    /// native HDP flush publishes the CPU writes.
    /// # Safety
    /// Exclude concurrent firmware/FAMS/display/HDP/clock/power writers and
    /// retain the owner and all inherited resources on every outcome.
    pub unsafe fn upload_surface(
        &mut self,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), Error> {
        self.1.upload(&mut self.0, pipe, x, y, pixels)
    }
}
