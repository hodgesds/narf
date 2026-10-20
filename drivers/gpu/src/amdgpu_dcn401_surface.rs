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
pub use cursor::{CursorApplied, CURSOR_MAX};
#[path = "amdgpu_dcn401_color.rs"]
mod color;
#[path = "amdgpu_dcn401_flip.rs"]
mod flip;
#[path = "amdgpu_dcn401_scanout.rs"]
mod scanout;
pub use color::{ColorProgram, GamutProgram, OgamProgram, PipeColor};
pub use flip::FlipDone;
pub use scanout::{
    LivePipe, OverlayScanout, ScanoutPosition, ScanoutRunning, ScanoutUnderflow, VblankPhase,
};

/// A single-plane packed RGB scanout format: the DRM fourccs amdgpu_dm
/// offers on a DCN4.0.1 primary plane that this path programs, each mapped
/// to its DC surface format as amdgpu_dm_plane_fill_dc_plane_info_and_addr
/// does (X and A variants share one; only the blending differs).
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
}
impl SurfaceFormat {
    /// Every format, in the order the native plane lists them.
    pub const ALL: [Self; 13] = [
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
        };
        u32::from_le_bytes(code)
    }
    /// The format of a DRM fourcc, if this path scans it out.
    pub fn from_fourcc(fourcc: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.fourcc() == fourcc)
    }
    /// Bytes per pixel: DML's 444_16, 444_32 or 444_64 source format.
    pub const fn bytes_per_pixel(self) -> u32 {
        match self {
            Self::Rgb565 => 2,
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
    /// hubp2_program_pixel_format's DCSURF_SURFACE_PIXEL_FORMAT: 3 RGB565,
    /// 8 A*GB8888, 10 A*GB2101010, 24 A*GB16161616F (the crossbar swaps
    /// the BGR orders).
    const fn hubp_pixel_format(self) -> u32 {
        match self {
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
    /// ROTATE_0 or ROTATE_180: DML refuses a linear surface scanned
    /// vertically (SourceFormatPixelAndScanSupport).
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
    /// ODM 2:1: the second pipe, whose HUBP fetches the right half of the
    /// same surface (and whose DPP/MPCC/DET follow it). Its own timing,
    /// surface slot and memory stay unused.
    pub odm: Option<u8>,
    /// The plane's placement; `None` is the whole surface unscaled on a
    /// stream of its own size, blended as `Blend::default_for` its format.
    pub plane: Option<PlaneLayout>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceApplied {
    pub request: SurfaceRequest,
    /// GPU framebuffer address, never a CPU BAR or translated physical address.
    pub address: u64,
    pub pitch_bytes: u32,
    /// Visible rows including pitch padding; the reservation is page-rounded.
    pub bytes: u64,
}
impl SurfaceRequest {
    fn geometry(self) -> Result<(u32, u64), Error> {
        if self.pipe >= 4
            || self.width == 0
            || self.height == 0
            || self.width > 0x3fff
            || self.height > 0x3fff
            || self
                .odm
                .is_some_and(|q| q >= 4 || q == self.pipe || self.width % 2 != 0)
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
                || !matches!(p.rotation, spl::Rotation::R0 | spl::Rotation::R180)
                || (p.blend.per_pixel_alpha && !self.format.cnvc_alpha())
            {
                return Err(Error::Invalid);
            }
            // Every pipe's SPL must succeed (resource_build_scaling_params).
            if self.scalers().any(|(_, scaler)| !scaler.ok) {
                return Err(Error::Unsupported);
            }
        }
        // Linear surfaces use 256-byte-aligned rows and page-aligned backing.
        let pitch = self.format.pitch_bytes(self.width);
        Ok((pitch, u64::from(pitch) * u64::from(self.height)))
    }
}
impl SurfaceRequest {
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
    /// Whether this is the unscaled full-frame plane of its stream.
    pub fn full_frame(self) -> bool {
        let l = self.layout();
        l.src == spl::Rect::new(0, 0, self.width as i32, self.height as i32)
            && l.dst == spl::Rect::new(0, 0, l.stream_width as i32, l.stream_height as i32)
            && l.stream_width == self.width
            && l.stream_height == self.height
            && l.rotation == spl::Rotation::R0
    }
    /// Each ODM segment's pipe and SPL's input for it, the request's own
    /// pipe first; the whole stream on that pipe without ODM.
    /// resource_get_odm_slice_src_rect: even halves, a 4:2:0 right half one
    /// pixel wider to the left.
    pub(in crate::amdgpu_dcn401_otg) fn spl_inputs(
        self,
    ) -> impl Iterator<Item = (u8, spl::Input)> + Clone {
        let l = self.layout();
        let (w, h) = (l.stream_width as i32, l.stream_height as i32);
        let half = if self.odm.is_some() { w / 2 } else { w };
        let edge = i32::from(l.ycbcr420);
        let input = move |odm_slice| spl::Input {
            src: l.src,
            dst: l.dst,
            clip: l.dst,
            stream_width: w,
            stream_height: h,
            odm_slice,
            rotation: l.rotation,
            horizontal_mirror: false,
            alpha: l.blend.per_pixel_alpha,
        };
        core::iter::once((self.pipe, input(spl::Rect::new(0, 0, half, h)))).chain(
            self.odm
                .map(move |q| (q, input(spl::Rect::new(half - edge, 0, w - half + edge, h)))),
        )
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
        let laid_out = self.plane.is_some();
        self.spl_inputs()
            .zip(self.segments())
            .map(move |((p, input), (_, x, width))| {
                let scaler = if laid_out {
                    spl::calculate(&input)
                } else {
                    spl::Scaler::unity(x as i32, width as i32, height)
                };
                (p, scaler)
            })
    }
    /// Each ODM segment's pipe, first stream column and width (its ODM
    /// slice's destination), the request's own pipe first; the whole
    /// stream on that pipe without ODM.
    pub(in crate::amdgpu_dcn401_otg) fn segments(
        self,
    ) -> impl Iterator<Item = (u8, u32, u32)> + Clone {
        let w = self.layout().stream_width;
        let width = if self.odm.is_some() { w / 2 } else { w };
        core::iter::once((self.pipe, 0, width)).chain(self.odm.map(move |q| (q, width, w - width)))
    }
    /// The plane as DC hands it to DML21 after SPL
    /// (populate_dml21_plane_config_from_plane_state): the surface, the
    /// whole-plane viewport, ratios and taps SPL computes on the whole
    /// stream (`dml::Plane::full` for the unscaled full-frame plane).
    pub fn dml_plane(self) -> crate::amdgpu_dcn401_dml::Plane {
        let bpp = self.format.bytes_per_pixel();
        let pitch = self.format.pitch_bytes(self.width) / bpp;
        let l = self.layout();
        let (w, h) = (l.stream_width as i32, l.stream_height as i32);
        let s = if self.plane.is_some() {
            spl::calculate(&spl::Input {
                src: l.src,
                dst: l.dst,
                clip: l.dst,
                stream_width: w,
                stream_height: h,
                odm_slice: spl::Rect::new(0, 0, w, h),
                rotation: l.rotation,
                horizontal_mirror: false,
                alpha: l.blend.per_pixel_alpha,
            })
        } else {
            spl::Scaler::unity(0, w, h)
        };
        let [v_taps, h_taps, _, _] = s.dc_taps();
        crate::amdgpu_dcn401_dml::Plane {
            surface_width: self.width,
            surface_height: self.height,
            pitch,
            bytes_per_pixel: bpp,
            viewport_width: s.viewport.width as u32,
            viewport_height: s.viewport.height as u32,
            h_ratio: s.ratios[0] >> 5,
            v_ratio: s.ratios[1] >> 5,
            h_taps,
            v_taps,
        }
    }
    /// Whether `other` fits the same buffers: the same pipe(s), size and
    /// format (the placement may differ).
    pub(in crate::amdgpu_dcn401_otg) fn same_allocation(self, other: Self) -> bool {
        (self.pipe, self.width, self.height, self.format, self.odm)
            == (
                other.pipe,
                other.width,
                other.height,
                other.format,
                other.odm,
            )
    }
    /// Every pipe the surface's fetch occupies, by bit.
    pub(in crate::amdgpu_dcn401_otg) fn pipe_mask(self) -> u8 {
        self.segments().fold(0, |m, (p, _, _)| m | bit(p))
    }
}
impl SurfaceApplied {
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
        Ok(u64::from(y) * u64::from(self.pitch_bytes) + first)
    }
    /// One segment's HUBP surface registers: the shared address and pitch,
    /// with SPL's viewport for that segment (hubp401_set_viewport, luma and
    /// chroma alike for RGB). hubp401_program_size's PITCH is in pixels,
    /// less one; hubp2_program_rotation and hubp2_program_pixel_format set
    /// the rotation, format and crossbar.
    fn registers(self, scaler: &spl::Scaler) -> [(u64, u32, u32); 18] {
        let format = self.request.format;
        let rotation = self.request.layout().rotation as u32;
        let [d, s, sd, ss, dc, sc, sdc, ssc] = crate::amdgpu_dcn401_dscl::viewport(scaler);
        [
            (0x612, 0x203, 0), // primary TMZ, both DCC enables
            (0x5e7, 7, 0),     // ADDR3 linear; DIM_TYPE stays at native 2D
            (
                0x607,
                0xffff,
                self.pitch_bytes / format.bytes_per_pixel() - 1,
            ),
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
            (0x60b, 0xffff, (self.address >> 32) as u32),
            // Low address publishes the flip: it must be the last surface write.
            (0x60a, u32::MAX, self.address as u32),
        ]
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
        let applied = SurfaceApplied {
            request,
            address: memory.address(),
            pitch_bytes,
            bytes,
        };
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
    /// pipe.
    pub(in crate::amdgpu_dcn401_otg) fn fetch_pipes(&self, pipe: u8) -> impl Iterator<Item = u8> {
        let odm = self
            .status
            .surfaces
            .get(usize::from(pipe))
            .copied()
            .flatten()
            .and_then(|a| a.request.odm);
        core::iter::once(pipe).chain(odm)
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
