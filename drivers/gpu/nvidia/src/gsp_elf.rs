//! GSP-RM firmware extraction — ELF sections + the RISC-V bootloader.
//!
//! The acquired `gsp.bin` is an ELF64 whose `.fwimage` section is the
//! GSP-RM image (RADIX3-mapped into WPR2) and whose `.fwsignature_*`
//! section holds its signatures. The `bootloader-<ver>.bin` is an
//! `nvfw` container wrapping an `RM_RISCV_UCODE_DESC` + the RISC-V
//! bootloader payload. This module extracts both — the last parsing
//! piece the live boot needs. Grounded against `/usr/src/linux`
//! `rm/r535/gsp.c::{r535_gsp_elf_section,r535_gsp_rm_boot_ctor}` +
//! `nvrm/gsp.h` `RM_RISCV_UCODE_DESC`, cross-referenced to nova-core
//! `firmware/gsp.rs` / `firmware/riscv.rs`.
//!
//! Pure CPU work (no hardware), unit-tested.

#![allow(dead_code)]

use crate::chip::ChipFamily;

// ── ELF64 section lookup ─────────────────────────────────────────
//
// The GSP firmware ELF is always 64-bit, little-endian; the lookup is
// name-only (`sh_type` is ignored). Field offsets per the ELF64 spec.

const EHDR_E_SHOFF: usize = 0x28; // u64
const EHDR_E_SHNUM: usize = 0x3c; // u16
const EHDR_E_SHSTRNDX: usize = 0x3e; // u16
const SHDR_SIZE: usize = 64;
const SHDR_SH_NAME: usize = 0x00; // u32
const SHDR_SH_OFFSET: usize = 0x18; // u64
const SHDR_SH_SIZE: usize = 0x20; // u64

fn rd16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn rd32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Find an ELF64 section by name and return its data slice. Mirrors
/// `r535_gsp_elf_section` / nova-core `elf64_section`.
pub fn elf64_section<'a>(elf: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let shoff = rd64(elf, EHDR_E_SHOFF)? as usize;
    let shnum = rd16(elf, EHDR_E_SHNUM)? as usize;
    let shstrndx = rd16(elf, EHDR_E_SHSTRNDX)? as usize;
    // The section-name string table's file offset.
    let str_off = {
        let sh = shoff.checked_add(shstrndx.checked_mul(SHDR_SIZE)?)?;
        rd64(elf, sh + SHDR_SH_OFFSET)? as usize
    };
    for i in 0..shnum {
        let sh = shoff.checked_add(i.checked_mul(SHDR_SIZE)?)?;
        let sh_name = rd32(elf, sh + SHDR_SH_NAME)? as usize;
        let name_at = str_off.checked_add(sh_name)?;
        let tail = elf.get(name_at..)?;
        let end = tail.iter().position(|&b| b == 0)?;
        if &tail[..end] == name.as_bytes() {
            let off = rd64(elf, sh + SHDR_SH_OFFSET)? as usize;
            let size = rd64(elf, sh + SHDR_SH_SIZE)? as usize;
            return elf.get(off..off.checked_add(size)?);
        }
    }
    None
}

/// The `.fwimage` section — the GSP-RM image.
pub const FWIMAGE_SECTION: &str = ".fwimage";

/// The `.fwsignature_*` section name for a chip family. The suffix is
/// a generation string, with GA100 sharing Turing's. Cite the per-chip
/// `.sig_section` in `nvkm/subdev/gsp/*.c` + nova-core `gsp.rs`.
pub fn signature_section(family: ChipFamily, asic: &str) -> Option<&'static str> {
    Some(match family {
        ChipFamily::Turing if matches!(asic, "tu116" | "tu117") => ".fwsignature_tu11x",
        ChipFamily::Turing => ".fwsignature_tu10x",
        // GA100 reuses the Turing firmware/signature; narf's table has
        // no GA100 ASIC, so all Ampere here is ga10x.
        ChipFamily::Ampere => ".fwsignature_ga10x",
        ChipFamily::Ada => ".fwsignature_ad10x",
        _ => return None,
    })
}

/// The two GSP-RM sections pulled from `gsp.bin`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GspRmSections<'a> {
    /// The GSP-RM image (`.fwimage`).
    pub fwimage: &'a [u8],
    /// The signatures (`.fwsignature_*`).
    pub signatures: &'a [u8],
}

/// Extract `.fwimage` + the chip's `.fwsignature_*` from `gsp.bin`.
pub fn gsp_rm_sections<'a>(
    gsp_bin: &'a [u8],
    family: ChipFamily,
    asic: &str,
) -> Option<GspRmSections<'a>> {
    let sig_name = signature_section(family, asic)?;
    Some(GspRmSections {
        fwimage: elf64_section(gsp_bin, FWIMAGE_SECTION)?,
        signatures: elf64_section(gsp_bin, sig_name)?,
    })
}

// ── RISC-V bootloader descriptor ─────────────────────────────────

/// `nvfw_bin_hdr.bin_magic` for the bootloader container. Cite
/// nova-core `BinHdr` (`magic == 0x10de`).
pub const NVFW_BIN_MAGIC: u32 = 0x10de;

/// The fields of `RM_RISCV_UCODE_DESC` the boot path consumes, plus
/// the ucode payload range within the blob. Cite
/// `r535_gsp_rm_boot_ctor`: `code/data/manifest_offset` come from the
/// `monitor*`/`manifest` descriptor fields and feed `GspFwWprMeta`;
/// `app_version` is written to the GSP Falcon OS register at boot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RiscvDesc {
    pub code_offset: u32,
    pub data_offset: u32,
    pub manifest_offset: u32,
    pub app_version: u32,
    /// Ucode payload within the bootloader blob (`bin_hdr.data_*`).
    pub ucode_start: usize,
    pub ucode_len: usize,
}

// RM_RISCV_UCODE_DESC field offsets (u32 each).
const RISCV_APP_VERSION: usize = 28;
const RISCV_MANIFEST_OFFSET: usize = 32;
const RISCV_MONITOR_DATA_OFFSET: usize = 40;
const RISCV_MONITOR_CODE_OFFSET: usize = 48;

/// Parse the `bootloader-<ver>.bin` blob: validate the `nvfw` header,
/// read `RM_RISCV_UCODE_DESC` at `header_offset`, and locate the
/// RISC-V ucode payload at `data_offset`. Mirrors
/// `r535_gsp_rm_boot_ctor`.
pub fn parse_riscv_desc(blob: &[u8]) -> Option<RiscvDesc> {
    // nvfw_bin_hdr: magic, ver, size, header_offset, data_offset, data_size.
    if rd32(blob, 0)? != NVFW_BIN_MAGIC {
        return None;
    }
    let header_offset = rd32(blob, 12)? as usize;
    let data_offset = rd32(blob, 16)? as usize;
    let data_size = rd32(blob, 20)? as usize;
    // The ucode payload must lie within the blob.
    let end = data_offset.checked_add(data_size)?;
    if end > blob.len() {
        return None;
    }
    let d = header_offset;
    Some(RiscvDesc {
        code_offset: rd32(blob, d + RISCV_MONITOR_CODE_OFFSET)?,
        data_offset: rd32(blob, d + RISCV_MONITOR_DATA_OFFSET)?,
        manifest_offset: rd32(blob, d + RISCV_MANIFEST_OFFSET)?,
        app_version: rd32(blob, d + RISCV_APP_VERSION)?,
        ucode_start: data_offset,
        ucode_len: data_size,
    })
}
