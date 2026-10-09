//! RLC (RunList Controller) firmware-header and autoload-table decoding.
//!
//! Reference: `drivers/gpu/drm/amd/amdgpu/amdgpu_ucode.h`
//! (`rlc_firmware_header_v2_0` … `_v2_3`), `amdgpu_rlc.h`
//! (`RLC_TABLE_OF_CONTENT`, `SOC21_FIRMWARE_ID`) and
//! `gfx_v11_0.c::gfx_v11_0_parse_rlc_toc`.
//!
//! The RLC is the piece of GFX microcode that orchestrates power-gating and
//! the GFX clock state machine. Its blob carries extra metadata past the
//! common 32-byte header: the jump table, the three save/restore lists
//! (CNTL, GPM, SRM), the register-list format arrays, and from v2.2 the
//! IRAM/DRAM images GFX11 needs.
//!
//! ## Header chain
//!
//! Every variant extends the previous one, so the offsets are cumulative and
//! `header_version_minor` says how far the blob goes. Offsets below are
//! file-relative bytes, taken from `offsetof` on the Linux structures:
//!
//! ```text
//! v2.0  0x00  common_firmware_header (32 bytes)
//!       0x20  ucode_feature_version
//!       0x24  jt_offset                                  (dwords)
//!       0x28  jt_size                                    (dwords)
//!       0x2c  save_and_restore_offset
//!       0x30  clear_state_descriptor_offset
//!       0x34  avail_scratch_ram_locations
//!       0x38  reg_restore_list_size
//!       0x3c  reg_list_format_start
//!       0x40  reg_list_format_separate_start
//!       0x44  starting_offsets_start
//!       0x48  reg_list_format_size_bytes
//!       0x4c  reg_list_format_array_offset_bytes
//!       0x50  reg_list_size_bytes
//!       0x54  reg_list_array_offset_bytes
//!       0x58  reg_list_format_separate_size_bytes
//!       0x5c  reg_list_format_separate_array_offset_bytes
//!       0x60  reg_list_separate_size_bytes
//!       0x64  reg_list_separate_array_offset_bytes       (ends at 0x68)
//! v2.1  0x68  reg_list_format_direct_reg_list_length
//!       0x6c  save_restore_list_cntl_{ucode_ver, feature_ver,
//!             size_bytes 0x74, offset_bytes 0x78}
//!       0x7c  save_restore_list_gpm_{…, size 0x84, offset 0x88}
//!       0x8c  save_restore_list_srm_{…, size 0x94, offset 0x98}  (ends 0x9c)
//! v2.2  0x9c  rlc_iram_ucode_size_bytes
//!       0xa0  rlc_iram_ucode_offset_bytes
//!       0xa4  rlc_dram_ucode_size_bytes
//!       0xa8  rlc_dram_ucode_offset_bytes                (ends at 0xac)
//! v2.3  0xac  rlcp_ucode_{version, feature_version, size 0xb4, offset 0xb8}
//!       0xbc  rlcv_ucode_{version, feature_version, size 0xc4, offset 0xc8}
//! ```
//!
//! ## The autoload table of contents
//!
//! The autoload TOC does **not** live in the RLC blob. It is the whole
//! content of the separate PSP TOC firmware (`psp_13_0_4_toc.bin` on
//! Phoenix), which `gfx_v11_0_parse_rlc_toc` walks from
//! `adev->psp.toc.start_addr`. Each entry is four dwords, with the id and the
//! size packed as bitfields rather than laid out as plain words:
//!
//! ```text
//! DW0  bits 24:0   offset  (dwords)
//!      bits 31:25  id      (SOC21_FIRMWARE_ID)
//! DW1  bit  0      load_at_boot
//!      bit  1      load_at_vddgfx
//!      bit  2      load_at_reset
//!      bits 4:3    memory_destination
//!      bits 8:5    vfflr_image_code
//!      bit  9      load_mode_direct
//!      bits 13:10  save_for_vddgfx, save_for_vfflr, reserved, signed_source
//!      bits 31:14  size    (dwords)
//! DW2  indirect_addr_reg : 16, index : 16
//! DW3  indirect_data_reg : 16, indirect_start_offset : 16
//! ```
//!
//! Both `offset` and `size` are dword counts; Linux multiplies each by four
//! to get bytes. The table has no length field and no zero terminator: the
//! walk stops at the first entry whose `id` falls outside
//! `(INVALID, MAX)` exclusive.

use core::fmt;

use crate::amdgpu_ucode_header::{self as ucode, CommonHeader, COMMON_HEADER_BYTES};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RlcError {
    /// Shorter than the common header, or `size_bytes` disagrees with the
    /// actual length.
    BadCommonHeader,
    /// `header_version_major` is not 2. Only the v2 chain is described here.
    UnsupportedMajor(u16),
    /// Shorter than the fields `header_version_minor` claims are present.
    Truncated,
    /// A size/offset pair points past the end of the blob.
    OutOfBounds,
}

impl fmt::Display for RlcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RlcError::BadCommonHeader => f.write_str("bad RLC common header"),
            RlcError::UnsupportedMajor(v) => write!(f, "unsupported RLC header major {v}"),
            RlcError::Truncated => f.write_str("RLC header truncated"),
            RlcError::OutOfBounds => f.write_str("RLC region out of bounds"),
        }
    }
}

/// One `(size_bytes, offset_bytes)` region named by the header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Region {
    pub size_bytes: u32,
    pub offset_bytes: u32,
}

/// The RLC v2 header, decoded as far as `header_version_minor` allows.
/// Everything past the declared minor stays `None` rather than reading
/// whatever follows.
#[derive(Copy, Clone, Debug, Default)]
pub struct RlcHeader {
    pub common: CommonHeader,
    pub minor: u16,
    pub ucode_feature_version: u32,
    /// Jump table, in **dwords** from the start of the ucode region — the
    /// same units `gfx_firmware_header_v1_0` uses.
    pub jt_offset_dw: u32,
    pub jt_size_dw: u32,
    pub clear_state_descriptor_offset: u32,
    pub reg_list_format_start: u32,
    pub reg_list_format_separate_start: u32,
    pub starting_offsets_start: u32,
    pub reg_list_format: Region,
    pub reg_list: Region,
    /// v2.1 and up: the three save/restore lists.
    pub save_restore_list_cntl: Option<Region>,
    pub save_restore_list_gpm: Option<Region>,
    pub save_restore_list_srm: Option<Region>,
    /// v2.2 and up: the images GFX11 loads into RLC IRAM and DRAM.
    pub iram: Option<Region>,
    pub dram: Option<Region>,
    /// v2.3 and up: the RLCP and RLCV co-processor images.
    pub rlcp: Option<Region>,
    pub rlcv: Option<Region>,
}

/// Byte at which each minor's own fields end — i.e. the minimum header
/// length for that minor. `sizeof` on the Linux structures.
const V2_0_END: usize = 0x68;
const V2_1_END: usize = 0x9c;
const V2_2_END: usize = 0xac;
const V2_3_END: usize = 0xcc;

/// Parse an RLC v2 header. `blob` is the whole firmware file.
pub fn parse(blob: &[u8]) -> Result<RlcHeader, RlcError> {
    let common = ucode::parse_common(blob).map_err(|_| RlcError::BadCommonHeader)?;
    if common.size_bytes as usize != blob.len() {
        // `amdgpu_ucode_validate` is exactly this check — there is no magic
        // number at offset zero to test instead.
        return Err(RlcError::BadCommonHeader);
    }
    if common.header_version_major != 2 {
        return Err(RlcError::UnsupportedMajor(common.header_version_major));
    }
    let minor = common.header_version_minor;
    let need = match minor {
        0 => V2_0_END,
        1 => V2_1_END,
        2 => V2_2_END,
        _ => V2_3_END,
    };
    if blob.len() < need {
        return Err(RlcError::Truncated);
    }
    let dw = |o: usize| u32::from_le_bytes([blob[o], blob[o + 1], blob[o + 2], blob[o + 3]]);
    let region = |size: usize, offset: usize| Region {
        size_bytes: dw(size),
        offset_bytes: dw(offset),
    };
    let mut header = RlcHeader {
        common,
        minor,
        ucode_feature_version: dw(0x20),
        jt_offset_dw: dw(0x24),
        jt_size_dw: dw(0x28),
        clear_state_descriptor_offset: dw(0x30),
        reg_list_format_start: dw(0x3c),
        reg_list_format_separate_start: dw(0x40),
        starting_offsets_start: dw(0x44),
        reg_list_format: region(0x48, 0x4c),
        reg_list: region(0x50, 0x54),
        ..RlcHeader::default()
    };
    if minor >= 1 {
        header.save_restore_list_cntl = Some(region(0x74, 0x78));
        header.save_restore_list_gpm = Some(region(0x84, 0x88));
        header.save_restore_list_srm = Some(region(0x94, 0x98));
    }
    if minor >= 2 {
        header.iram = Some(region(0x9c, 0xa0));
        header.dram = Some(region(0xa4, 0xa8));
    }
    if minor >= 3 {
        header.rlcp = Some(region(0xb4, 0xb8));
        header.rlcv = Some(region(0xc4, 0xc8));
    }
    for region in [
        Some(header.reg_list_format),
        Some(header.reg_list),
        header.save_restore_list_cntl,
        header.save_restore_list_gpm,
        header.save_restore_list_srm,
        header.iram,
        header.dram,
        header.rlcp,
        header.rlcv,
    ]
    .into_iter()
    .flatten()
    {
        if region.size_bytes == 0 {
            continue;
        }
        let end = region
            .offset_bytes
            .checked_add(region.size_bytes)
            .ok_or(RlcError::OutOfBounds)?;
        if region.offset_bytes < COMMON_HEADER_BYTES as u32 || end as usize > blob.len() {
            return Err(RlcError::OutOfBounds);
        }
    }
    Ok(header)
}

/// Slice one of the header's regions out of the blob. `parse` has already
/// bounds-checked every region it returned, so this cannot fail for a region
/// that came from the same header.
pub fn region<'a>(blob: &'a [u8], region: &Region) -> Option<&'a [u8]> {
    let end = region.offset_bytes.checked_add(region.size_bytes)?;
    blob.get(region.offset_bytes as usize..end as usize)
}

// ── Autoload table of contents ────────────────────────────────────

/// `SOC21_FIRMWARE_ID_INVALID`. The walk stops on an id at or below this.
pub const FIRMWARE_ID_INVALID: u32 = 0;
/// `SOC21_FIRMWARE_ID_MAX` for GFX11 (`amdgpu_rlc.h`). The walk stops on an
/// id at or above this, which is how the table ends: there is no count and no
/// terminator entry.
pub const FIRMWARE_ID_MAX: u32 = 37;
/// `sizeof(RLC_TABLE_OF_CONTENT)` — four dwords.
pub const TOC_ENTRY_BYTES: usize = 16;

/// One decoded TOC entry. `offset` and `size` are bytes; the on-disk
/// bitfields hold dword counts, which Linux scales by four.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AutoloadEntry {
    pub firmware_id: u32,
    pub offset: u32,
    pub size: u32,
    /// `memory_destination`, DW1 bits 4:3.
    pub memory_destination: u32,
    /// `load_at_boot`, DW1 bit 0.
    pub load_at_boot: bool,
    /// `signed_source`, DW1 bit 13.
    pub signed_source: bool,
}

/// Walk the autoload table of contents.
///
/// `toc` is the **PSP TOC firmware payload** — not the RLC blob. Iteration
/// stops at the first entry whose id leaves `(INVALID, MAX)`, or when fewer
/// than one entry's worth of bytes remain.
pub fn autoload_iter(toc: &[u8]) -> impl Iterator<Item = AutoloadEntry> + '_ {
    (0..toc.len() / TOC_ENTRY_BYTES)
        .map(move |i| {
            let at = i * TOC_ENTRY_BYTES;
            let dw = |n: usize| {
                let o = at + n * 4;
                u32::from_le_bytes([toc[o], toc[o + 1], toc[o + 2], toc[o + 3]])
            };
            let (dw0, dw1) = (dw(0), dw(1));
            AutoloadEntry {
                firmware_id: dw0 >> 25,
                // Bits 24:0, scaled from dwords to bytes. The field is 25
                // bits so the product cannot overflow a u32.
                offset: (dw0 & 0x01ff_ffff) * 4,
                // Bits 31:14, likewise 18 bits wide.
                size: (dw1 >> 14) * 4,
                memory_destination: (dw1 >> 3) & 0x3,
                load_at_boot: dw1 & 1 != 0,
                signed_source: dw1 & (1 << 13) != 0,
            }
        })
        .take_while(|e| e.firmware_id > FIRMWARE_ID_INVALID && e.firmware_id < FIRMWARE_ID_MAX)
}

/// Total size of the autoload image, as `gfx_v11_0_calc_toc_total_size`
/// computes it: the sum of every region, raised to cover the last region if
/// the table's offsets are padded apart.
pub fn autoload_total_size(toc: &[u8]) -> u32 {
    let mut total: u32 = 0;
    let mut last_end: u32 = 0;
    for entry in autoload_iter(toc) {
        total = total.saturating_add(entry.size);
        last_end = last_end.max(entry.offset.saturating_add(entry.size));
    }
    total.max(last_end)
}
