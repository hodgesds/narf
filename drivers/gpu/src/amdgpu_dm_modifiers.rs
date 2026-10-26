//! GFX12 framebuffer modifiers as amdgpu exposes them on the native
//! RX 9070 XT (GC 12.0.1, DCN 4.0.1) card, and the framebuffer checks that
//! go with them. Linux references:
//!
//! - `include/uapi/drm/drm_fourcc.h`: the AMD_FMT_MOD fields.
//! - `amdgpu_dm_plane.c`: `amdgpu_dm_plane_add_gfx12_modifiers` and
//!   `amdgpu_dm_plane_get_plane_modifiers` (the list every primary and
//!   overlay plane advertises), `amdgpu_dm_plane_format_mod_supported` (the
//!   per-format masks of the IN_FORMATS blob, drm_plane.c
//!   `create_in_format_blob`),
//!   `amdgpu_dm_plane_fill_gfx12_attrs_from_modifiers` (the tiling and DCC
//!   DC programs) and `amdgpu_dm_plane_validate_dcc` with DCN401's
//!   `hubbub401_get_dcc_compression_cap`.
//! - `amdgpu_display.c`: `convert_tiling_flags_to_modifier_gfx12`,
//!   `amdgpu_display_verify_sizes` / `amdgpu_display_verify_plane` and
//!   `amdgpu_display_framebuffer_init`'s single-BO rule.
//! - `drm_framebuffer.c`: `framebuffer_check`; `drm_fourcc.c`: the
//!   `drm_format_info` of the formats amdgpu_dm lists on DCN4.
//!
//! Nothing here touches hardware.

/// The ADDFB2 wire request itself is a vendor-neutral UAPI layout and
/// lives in the DRM core; re-exported here so existing paths keep
/// resolving.
pub use crate::drm::fb_cmd::{FbCmd, FB_INTERLACED, FB_MODIFIERS};

/// DRM_FORMAT_MOD_LINEAR.
pub const LINEAR: u64 = 0;
/// DRM_FORMAT_MOD_INVALID (fourcc_mod_code(NONE, DRM_FORMAT_RESERVED)).
pub const INVALID: u64 = 0x00ff_ffff_ffff_ffff;
/// AMD_FMT_MOD: fourcc_mod_code(AMD, 0) (DRM_FORMAT_MOD_VENDOR_AMD 0x02).
pub const AMD_FMT_MOD: u64 = 0x02 << 56;
/// AMD_FMT_MOD_TILE_VER_GFX12.
pub const TILE_VER_GFX12: u64 = 5;
/// AMD_FMT_MOD_TILE_VER_GFX11, the last version with the GFX9 rules.
const TILE_VER_GFX11: u64 = 4;
const TILE_VERSION_SHIFT: u32 = 0;
const TILE_SHIFT: u32 = 8;
const DCC_SHIFT: u32 = 13;
const DCC_MAX_COMPRESSED_BLOCK_SHIFT: u32 = 18;

/// AMD_FMT_MOD_GET(TILE_VERSION).
pub const fn tile_version(modifier: u64) -> u64 {
    (modifier >> TILE_VERSION_SHIFT) & 0xff
}
/// AMD_FMT_MOD_GET(TILE).
pub const fn tile(modifier: u64) -> u64 {
    (modifier >> TILE_SHIFT) & 0x1f
}
/// AMD_FMT_MOD_GET(DCC).
pub const fn dcc(modifier: u64) -> bool {
    (modifier >> DCC_SHIFT) & 1 != 0
}
/// AMD_FMT_MOD_GET(DCC_MAX_COMPRESSED_BLOCK).
pub const fn dcc_max_compressed_block(modifier: u64) -> u64 {
    (modifier >> DCC_MAX_COMPRESSED_BLOCK_SHIFT) & 3
}
/// IS_AMD_FMT_MOD.
pub const fn is_amd(modifier: u64) -> bool {
    modifier >> 56 == 0x02
}

/// The GFX12 swizzle modes a modifier's TILE names
/// (AMD_FMT_MOD_TILE_GFX12_*, equal to DC's `swizzle_mode_addr3_values`,
/// which HUBP's DCSURF_TILING_CONFIG.SW_MODE takes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Swizzle {
    #[default]
    Linear = 0,
    S256B2D = 1,
    S4K2D = 2,
    S64K2D = 3,
    S256K2D = 4,
}
impl Swizzle {
    /// log2 of the swizzle block's size in bytes
    /// (amdgpu_display_verify_sizes' block_size_log2; LINEAR's 256-byte
    /// pitch unit).
    pub const fn block_log2(self) -> u32 {
        match self {
            Self::Linear | Self::S256B2D => 8,
            Self::S4K2D => 12,
            Self::S64K2D => 16,
            Self::S256K2D => 18,
        }
    }
    /// The block's width and height in pixels of `cpp` bytes
    /// (get_block_dimensions; LINEAR is 256 bytes wide and one row high).
    pub const fn block(self, cpp: u32) -> (u32, u32) {
        if matches!(self, Self::Linear) {
            return (256 / cpp, 1);
        }
        let pixel_log2 = self.block_log2() - cpp.trailing_zeros();
        let width_log2 = pixel_log2.div_ceil(2);
        (1 << width_log2, 1 << (pixel_log2 - width_log2))
    }
}

/// DCC's maximum compressed block (AMD_FMT_MOD_DCC_BLOCK_*), as
/// amdgpu_dm_plane_fill_gfx12_attrs_from_modifiers turns it into DC's
/// `dcc_ind_blk` (hubp_ind_block_64b / 128b / unconstrained).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DccBlock {
    B64 = 0,
    B128 = 1,
    B256 = 2,
}

/// What a modifier makes DC program: the swizzle and, with DCC, its
/// maximum compressed block (`dcc->independent_64b_blks` is `B64`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tiling {
    pub swizzle: Swizzle,
    pub dcc: Option<DccBlock>,
}
impl Tiling {
    pub const LINEAR: Self = Self {
        swizzle: Swizzle::Linear,
        dcc: None,
    };
    /// The modifier naming this tiling (LINEAR without a swizzle).
    pub const fn modifier(self) -> u64 {
        if matches!(self.swizzle, Swizzle::Linear) && self.dcc.is_none() {
            return LINEAR;
        }
        let mut m = AMD_FMT_MOD | TILE_VER_GFX12 << TILE_VERSION_SHIFT;
        m |= (self.swizzle as u64) << TILE_SHIFT;
        if let Some(b) = self.dcc {
            m |= 1 << DCC_SHIFT | (b as u64) << DCC_MAX_COMPRESSED_BLOCK_SHIFT;
        }
        m
    }
    /// amdgpu_dm_plane_fill_gfx12_attrs_from_modifiers for a framebuffer's
    /// modifier: LINEAR, or a GFX12 one's swizzle and (with DCC) max
    /// compressed block. A framebuffer added without modifiers may carry a
    /// GFX12 modifier the planes do not list (its BO's tiling flags name any
    /// max block), which Linux scans the same way. `None` for a modifier no
    /// GC 12 framebuffer can have.
    pub fn from_modifier(modifier: u64) -> Option<Self> {
        if modifier == LINEAR {
            return Some(Self::LINEAR);
        }
        if !is_amd(modifier) || tile_version(modifier) != TILE_VER_GFX12 {
            return None;
        }
        let swizzle = match tile(modifier) {
            1 => Swizzle::S256B2D,
            2 => Swizzle::S4K2D,
            3 => Swizzle::S64K2D,
            4 => Swizzle::S256K2D,
            _ => return None,
        };
        let dcc = dcc(modifier).then(|| match dcc_max_compressed_block(modifier) {
            0 => DccBlock::B64,
            1 => DccBlock::B128,
            _ => DccBlock::B256,
        });
        Some(Self { swizzle, dcc })
    }
}

/// amdgpu_dm_plane_get_plane_modifiers for a GC 12 primary or overlay
/// plane (amdgpu_dm_plane_add_gfx12_modifiers, then LINEAR; the INVALID
/// terminator is not one of the plane's modifiers): with DCC, every max
/// compressed block (256B, 128B, 64B) of each swizzle from 256K down, then
/// the swizzles without DCC.
pub const PLANE_MODIFIERS: [u64; 17] = {
    const SWIZZLES: [Swizzle; 4] = [
        Swizzle::S256K2D,
        Swizzle::S64K2D,
        Swizzle::S4K2D,
        Swizzle::S256B2D,
    ];
    const BLOCKS: [DccBlock; 3] = [DccBlock::B256, DccBlock::B128, DccBlock::B64];
    let mut out = [LINEAR; 17];
    let mut i = 0;
    while i < 12 {
        out[i] = Tiling {
            swizzle: SWIZZLES[i / 3],
            dcc: Some(BLOCKS[i % 3]),
        }
        .modifier();
        i += 1;
    }
    while i < 16 {
        out[i] = Tiling {
            swizzle: SWIZZLES[i - 12],
            dcc: None,
        }
        .modifier();
        i += 1;
    }
    out
};

/// amdgpu_dm_plane_get_plane_formats for a DCN401 primary or overlay plane
/// (both DC_PLANE_TYPE_DCN_UNIVERSAL with nv12, p010 and fp16 support):
/// rgb_formats, NV12, P010, then the four FP16 orders.
pub const DM_PLANE_FORMATS: [u32; 20] = {
    const CODES: [&[u8; 4]; 20] = [
        b"XR24", b"AR24", b"RA24", b"XR30", b"XB30", b"AR30", b"AB30", b"XR48", b"XB48", b"AR48",
        b"AB48", b"XB24", b"AB24", b"RG16", b"NV12", b"P010", b"XR4H", b"AR4H", b"XB4H", b"AB4H",
    ];
    let mut out = [0; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = u32::from_le_bytes(*CODES[i]);
        i += 1;
    }
    out
};

/// The `drm_format_info` fields these checks use, for the formats amdgpu_dm
/// lists on DCN4 planes (drm_fourcc.c): planes, bytes per pixel (P010's
/// char_per_block over its 1x1 blocks) and chroma subsampling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatInfo {
    pub fourcc: u32,
    pub num_planes: u32,
    pub cpp: [u32; 2],
    pub hsub: u32,
    pub vsub: u32,
}

/// DRM_FORMAT_NV12 ("NV12").
pub const NV12: u32 = u32::from_le_bytes(*b"NV12");
/// DRM_FORMAT_P010 ("P010").
pub const P010: u32 = u32::from_le_bytes(*b"P010");
/// DRM_FORMAT_NV21 ("NV21"), on amdgpu_dm's overlay list only for planes
/// that are not universal; DCN4's are.
pub const NV21: u32 = u32::from_le_bytes(*b"NV21");

/// drm_format_info for `fourcc`, if it is one amdgpu_dm can list.
pub fn format_info(fourcc: u32) -> Option<FormatInfo> {
    let packed = |cpp| FormatInfo {
        fourcc,
        num_planes: 1,
        cpp: [cpp, 0],
        hsub: 1,
        vsub: 1,
    };
    let semi = |cpp| FormatInfo {
        fourcc,
        num_planes: 2,
        cpp,
        hsub: 2,
        vsub: 2,
    };
    Some(match &fourcc.to_le_bytes() {
        b"XR24" | b"AR24" | b"RA24" | b"XB24" | b"AB24" | b"XR30" | b"XB30" | b"AR30" | b"AB30" => {
            packed(4)
        }
        b"RG16" => packed(2),
        b"XR48" | b"XB48" | b"AR48" | b"AB48" | b"XR4H" | b"AR4H" | b"XB4H" | b"AB4H" => packed(8),
        b"NV12" | b"NV21" => semi([1, 2]),
        b"P010" => semi([2, 4]),
        _ => return None,
    })
}

/// amdgpu_dm_plane_format_mod_supported for a primary or overlay plane
/// listing `PLANE_MODIFIERS`: LINEAR (and INVALID) always; any other only
/// when the plane lists it. GFX12 modifiers carry none of GFX9-11's
/// per-format limits, so every format takes every one.
pub fn format_mod_supported(fourcc: u32, modifier: u64) -> bool {
    if format_info(fourcc).is_none() {
        return false;
    }
    if modifier == LINEAR || modifier == INVALID {
        return true;
    }
    if !PLANE_MODIFIERS.contains(&modifier) {
        return false;
    }
    // GFX12 has no D-swizzle or DCC bpp/plane-count rules; those apply
    // only up to TILE_VER_GFX11.
    tile_version(modifier) > TILE_VER_GFX11
}

/// drm_plane.c create_in_format_blob for a plane of `formats` listing
/// `PLANE_MODIFIERS`: a version-1 `drm_format_modifier_blob`, the formats at
/// offset 24, then (8-byte aligned) one `drm_format_modifier` per modifier
/// with the mask of the formats amdgpu_dm_plane_format_mod_supported takes
/// it for.
pub fn in_formats_blob(formats: &[u32]) -> Option<alloc::vec::Vec<u8>> {
    let n = formats.len();
    if n == 0 || n > 64 {
        return None;
    }
    let formats_offset = 24u32;
    let modifiers_offset = (formats_offset + 4 * n as u32 + 7) & !7;
    let count = PLANE_MODIFIERS.len() as u32;
    let mut out = alloc::vec::Vec::with_capacity(modifiers_offset as usize + 24 * count as usize);
    for word in [1, 0, n as u32, formats_offset, count, modifiers_offset] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for &f in formats {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out.resize(modifiers_offset as usize, 0);
    for m in PLANE_MODIFIERS {
        let mask = formats
            .iter()
            .enumerate()
            .filter(|&(_, &f)| format_mod_supported(f, m))
            .fold(0u64, |mask, (j, _)| mask | 1 << j);
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(&[0; 8]); // offset, pad
        out.extend_from_slice(&m.to_le_bytes());
    }
    Some(out)
}

/// AMDGPU_TILING_GFX12_SWIZZLE_MODE and _DCC_MAX_COMPRESSED_BLOCK.
const TILING_GFX12_SWIZZLE_MODE_MASK: u64 = 0x7;
const TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT: u32 = 3;

/// convert_tiling_flags_to_modifier_gfx12: a framebuffer added without
/// DRM_MODE_FB_MODIFIERS takes its BO's GEM_METADATA tiling flags (and its
/// AMDGPU_GEM_CREATE_GFX12_DCC flag) as a modifier.
pub const fn from_tiling_flags(tiling_flags: u64, gfx12_dcc: bool) -> u64 {
    let swizzle = tiling_flags & TILING_GFX12_SWIZZLE_MODE_MASK;
    if swizzle == 0 {
        return LINEAR;
    }
    let max_comp_block = (tiling_flags >> TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT) & 3;
    AMD_FMT_MOD
        | TILE_VER_GFX12 << TILE_VERSION_SHIFT
        | swizzle << TILE_SHIFT
        | (gfx12_dcc as u64) << DCC_SHIFT
        | max_comp_block << DCC_MAX_COMPRESSED_BLOCK_SHIFT
}

/// Why a framebuffer is refused: `framebuffer_check` and amdgpu's checks
/// return -EINVAL for all of them except the -ERANGE overflows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FbError {
    Invalid,
    Range,
}

/// drm_framebuffer.c framebuffer_check (after drm_internal_framebuffer_create
/// found `info` for the format).
pub fn framebuffer_check(info: &FormatInfo, r: &FbCmd) -> Result<(), FbError> {
    if r.width == 0 || r.height == 0 {
        return Err(FbError::Invalid);
    }
    let modifiers = r.flags & FB_MODIFIERS != 0;
    for i in 0..info.num_planes as usize {
        let (sub_w, sub_h) = if i == 0 {
            (1, 1)
        } else {
            (info.hsub, info.vsub)
        };
        let width = r.width.div_ceil(sub_w);
        let height = r.height.div_ceil(sub_h);
        let min_pitch = u64::from(width) * u64::from(info.cpp[i]);
        if r.handles[i] == 0 {
            return Err(FbError::Invalid);
        }
        if min_pitch > u64::from(u32::MAX) {
            return Err(FbError::Range);
        }
        if u64::from(height) * u64::from(r.pitches[i]) + u64::from(r.offsets[i])
            > u64::from(u32::MAX)
        {
            return Err(FbError::Range);
        }
        if u64::from(r.pitches[i]) < min_pitch {
            return Err(FbError::Invalid);
        }
        if r.modifier[i] != 0 && !modifiers {
            return Err(FbError::Invalid);
        }
        if modifiers && r.modifier[i] != r.modifier[0] {
            return Err(FbError::Invalid);
        }
    }
    for i in info.num_planes as usize..4 {
        if r.modifier[i] != 0 {
            return Err(FbError::Invalid);
        }
        if !modifiers {
            continue;
        }
        if r.handles[i] != 0 || r.pitches[i] != 0 || r.offsets[i] != 0 {
            return Err(FbError::Invalid);
        }
    }
    Ok(())
}

/// amdgpu_display_verify_sizes for a GFX12 (or LINEAR) modifier on a BO of
/// `bo_size` bytes: each plane's pitch is a whole number of swizzle blocks
/// wide and at least the plane's width, its offset block aligned, and the
/// block rows of its height fit the BO. GFX12 DCC has no metadata plane.
pub fn verify_sizes(
    info: &FormatInfo,
    r: &FbCmd,
    modifier: u64,
    bo_size: u64,
) -> Result<(), FbError> {
    let swizzle = if modifier == LINEAR {
        Swizzle::Linear
    } else if tile_version(modifier) >= TILE_VER_GFX12 {
        match tile(modifier) {
            1 => Swizzle::S256B2D,
            2 => Swizzle::S4K2D,
            3 => Swizzle::S64K2D,
            4 => Swizzle::S256K2D,
            _ => return Err(FbError::Invalid),
        }
    } else {
        // Older tile versions never reach a GC 12 plane (format_mod_supported
        // refused them first).
        return Err(FbError::Invalid);
    };
    for i in 0..info.num_planes as usize {
        let cpp = info.cpp[i];
        let (block_width, block_height) = swizzle.block(cpp);
        verify_plane(
            r,
            i,
            info,
            block_width,
            block_height,
            swizzle.block_log2(),
            bo_size,
        )?;
    }
    Ok(())
}

/// amdgpu_display_verify_plane.
fn verify_plane(
    r: &FbCmd,
    plane: usize,
    info: &FormatInfo,
    block_width: u32,
    block_height: u32,
    block_size_log2: u32,
    bo_size: u64,
) -> Result<(), FbError> {
    let (sub_w, sub_h) = if plane > 0 {
        (info.hsub, info.vsub)
    } else {
        (1, 1)
    };
    let width = r.width / sub_w;
    let height = r.height / sub_h;
    let cpp = info.cpp[plane];
    let block_pitch = block_width * cpp;
    let min_pitch = (width * cpp).div_ceil(block_pitch) * block_pitch;
    let block_size = 1u32 << block_size_log2;
    if r.pitches[plane] % block_pitch != 0 || r.pitches[plane] < min_pitch {
        return Err(FbError::Invalid);
    }
    if r.offsets[plane] % block_size != 0 {
        return Err(FbError::Invalid);
    }
    let size = u64::from(r.offsets[plane])
        + u64::from(r.pitches[plane] / block_pitch)
            * u64::from(block_size)
            * u64::from(height.div_ceil(block_height));
    if bo_size < size {
        return Err(FbError::Invalid);
    }
    Ok(())
}

/// The bytes plane `plane` (of `height` luma rows and `pitch` bytes) spans
/// from its offset, as amdgpu_display_verify_plane sizes it.
pub fn plane_bytes(
    info: &FormatInfo,
    swizzle: Swizzle,
    height: u32,
    pitch: u32,
    plane: usize,
) -> u64 {
    let sub_h = if plane > 0 { info.vsub } else { 1 };
    let cpp = info.cpp[plane];
    let (block_width, block_height) = swizzle.block(cpp);
    u64::from(pitch / (block_width * cpp))
        * (1u64 << swizzle.block_log2())
        * u64::from((height / sub_h).div_ceil(block_height))
}

/// amdgpu_dm's mode_config max_width / max_height.
pub const MAX_FB_SIZE: u32 = 16384;

/// drm_internal_framebuffer_create up to the driver's fb_create: the flags,
/// amdgpu_dm's 16384x16384 bounds, a format DRM knows, then
/// framebuffer_check. Returns the format's info.
pub fn check_fb_cmd(r: &FbCmd) -> Result<FormatInfo, FbError> {
    if r.flags & !(FB_INTERLACED | FB_MODIFIERS) != 0
        || r.width > MAX_FB_SIZE
        || r.height > MAX_FB_SIZE
    {
        return Err(FbError::Invalid);
    }
    let info = format_info(r.pixel_format).ok_or(FbError::Invalid)?;
    framebuffer_check(&info, r)?;
    Ok(info)
}

/// amdgpu_display_gem_fb_verify_and_init after the BO lookup: some plane
/// takes the format with modifier[0] (drm_any_plane_has_format), every
/// plane names the same BO (amdgpu_display_framebuffer_init), a
/// framebuffer added without modifiers takes its BO's tiling flags
/// (convert_tiling_flags_to_modifier_gfx12), and the planes fit the BO
/// (amdgpu_display_verify_sizes). Returns the framebuffer's modifier.
pub fn check_amdgpu_fb(
    r: &FbCmd,
    info: &FormatInfo,
    plane_formats: &[u32],
    tiling_flags: u64,
    gfx12_dcc: bool,
    bo_size: u64,
) -> Result<u64, FbError> {
    if !plane_formats.contains(&r.pixel_format)
        || !format_mod_supported(r.pixel_format, r.modifier[0])
    {
        return Err(FbError::Invalid);
    }
    for i in 1..info.num_planes as usize {
        if r.handles[i] != r.handles[0] {
            return Err(FbError::Invalid);
        }
    }
    let modifier = if r.flags & FB_MODIFIERS != 0 {
        r.modifier[0]
    } else {
        from_tiling_flags(tiling_flags, gfx12_dcc)
    };
    verify_sizes(info, r, modifier, bo_size)?;
    Ok(modifier)
}

/// DCN401's dc caps `dcc_plane_width_limit`: set only for a GC 12.0.0
/// (external revision 0x40..0x50, Navi44) part, 7680. Navi48 is GC 12.0.1,
/// whose external revision is rev_id + 0x50, so it has none.
fn dcc_plane_width_limit() -> u32 {
    crate::amdgpu_rdna4::bound().map_or(0, |die| die.dcc_plane_width_limit())
}

/// amdgpu_dm_plane_validate_dcc for a DCC modifier on DCN401: DC's
/// hubbub401_get_dcc_compression_cap. amdgpu_dm hands it only the format,
/// surface size, the GFX9 swizzle field and the scan direction (its
/// `swizzle_mode_addr3` and pitches stay zero, so the linear branch of
/// hubbub401_dcc_support_swizzle always passes), so a surface is capable
/// when its format has a DCC element size and it is within the plane width
/// limit. It never sets `independent_64b_blks`, so any max compressed block
/// passes.
pub fn dcc_capable(fourcc: u32, width: u32) -> bool {
    let limit = dcc_plane_width_limit();
    if limit != 0 && width > limit {
        return false;
    }
    // hubbub401_dcc_support_pixel_format: every format DCN4 planes list
    // (RGB565, 8888, 2101010, 16161616(F) and the 4:2:0 video formats).
    format_info(fourcc).is_some()
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const VECTORS: &str = include_str!("../tests/amd_modifiers/vectors.txt");

    fn hex(v: &str) -> u64 {
        u64::from_str_radix(v.trim_start_matches("0x"), 16).unwrap()
    }
    fn fourcc(s: &str) -> u32 {
        let b = s.as_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }
    fn err(r: Result<(), FbError>) -> i32 {
        match r {
            Ok(()) => 0,
            Err(FbError::Invalid) => -22,
            Err(FbError::Range) => -34,
        }
    }

    fn answer(input: &str) -> String {
        use core::fmt::Write;
        let mut f = input.split_whitespace();
        let mut out = String::new();
        match f.next().unwrap() {
            "M" | "P" => {
                // The primary's list, then the overlay's: the same on DCN4.
                for plane in 0..2 {
                    if plane > 0 {
                        out.push_str(" |");
                    }
                    if input.starts_with('M') {
                        for (i, m) in PLANE_MODIFIERS.iter().enumerate() {
                            if i > 0 || plane > 0 {
                                out.push(' ');
                            }
                            let _ = write!(out, "{m:x}");
                        }
                    } else {
                        for (i, f) in DM_PLANE_FORMATS.iter().enumerate() {
                            if i > 0 || plane > 0 {
                                out.push(' ');
                            }
                            out.push_str(core::str::from_utf8(&f.to_le_bytes()).unwrap());
                        }
                    }
                }
            }
            "B" => {
                let formats: Vec<u32> = f.map(fourcc).collect();
                for b in in_formats_blob(&formats).unwrap() {
                    let _ = write!(out, "{b:02x}");
                }
            }
            "F" => {
                let format = fourcc(f.next().unwrap());
                let m = hex(f.next().unwrap());
                let _ = write!(out, "{}", u8::from(format_mod_supported(format, m)));
            }
            "T" => {
                let flags = hex(f.next().unwrap());
                let dcc = f.next().unwrap() == "1";
                let _ = write!(out, "{:x}", from_tiling_flags(flags, dcc));
            }
            "A" => {
                let format = fourcc(f.next().unwrap());
                let mut v = || hex(f.next().unwrap());
                let (width, height, flags) = (v() as u32, v() as u32, v() as u32);
                let mut cmd = FbCmd {
                    width,
                    height,
                    pixel_format: format,
                    flags,
                    ..FbCmd::default()
                };
                for i in 0..4 {
                    cmd.handles[i] = v() as u32;
                    cmd.pitches[i] = v() as u32;
                    cmd.offsets[i] = v() as u32;
                    cmd.modifier[i] = v();
                }
                let tiling = v();
                let dcc = v() != 0;
                let bo = v();
                let _ = write!(out, "{}", addfb_result(&cmd, tiling, dcc, bo));
            }
            other => panic!("unknown vector kind {other}"),
        }
        out
    }

    /// The ADDFB2 decision on a DCN4 plane's formats and modifiers: the
    /// framebuffer's modifier, or the error.
    fn addfb_result(cmd: &FbCmd, tiling: u64, dcc: bool, bo: u64) -> String {
        use core::fmt::Write;
        let mut out = String::new();
        let r = check_fb_cmd(cmd)
            .and_then(|info| check_amdgpu_fb(cmd, &info, &DM_PLANE_FORMATS, tiling, dcc, bo));
        match r {
            Ok(m) => {
                let _ = write!(out, "0 {m:x}");
            }
            Err(e) => {
                let _ = write!(out, "{}", err(Err(e)));
            }
        }
        out
    }

    fn amd_modifiers_match_linux_vectors() -> TestResult {
        let mut n = 0;
        for line in VECTORS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let (input, want) = line.split_once(" = ").unwrap();
            let got = answer(input);
            if got != want {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amd_modifiers: {input}: got {got}, want {want}"
                );
                return TestResult::Fail("vector mismatch");
            }
            n += 1;
        }
        if n < 100 {
            return TestResult::Fail("too few vectors");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/drm", amd_modifiers_match_linux_vectors);

    /// The list's shape: 12 DCC entries (256K first, max block 256B first),
    /// the four plain swizzles, LINEAR last; every entry maps back.
    fn amd_modifiers_gfx12_list_shape() -> TestResult {
        assert_eq!(PLANE_MODIFIERS[0], 0x0200_0000_0008_2405);
        assert_eq!(PLANE_MODIFIERS[12], 0x0200_0000_0000_0405);
        assert_eq!(PLANE_MODIFIERS[16], LINEAR);
        for m in PLANE_MODIFIERS {
            let t = Tiling::from_modifier(m).unwrap();
            assert_eq!(t.modifier(), m);
        }
        assert!(Tiling::from_modifier(INVALID).is_none());
        assert_eq!(Swizzle::S64K2D.block(4), (128, 128));
        assert_eq!(Swizzle::S256K2D.block(8), (256, 128));
        assert_eq!(Swizzle::S4K2D.block(1), (64, 64));
        assert_eq!(Swizzle::S256B2D.block(2), (16, 8));
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/drm", amd_modifiers_gfx12_list_shape);
}
