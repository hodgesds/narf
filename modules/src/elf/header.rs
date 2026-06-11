//! ELF64 header + section header + program header decoding for
//! relocatable kernel-module objects.
//!
//! Linux ref: `linux/include/uapi/linux/elf.h` and
//! `linux/kernel/module/main.c::elf_validity_cache_copy` (`main.c:1788`)
//! for the validation policy. We diverge slightly: NARF modules are
//! always `ET_REL` (relocatable), the kernel-side relocator places
//! sections wherever it wants, and a final symbol resolution pass
//! patches references. We don't accept `ET_EXEC` / `ET_DYN` because
//! domain placement + cap-typed exports require the kernel to own
//! layout decisions.

use core::convert::TryInto;

/// ELF identification offsets per the ELF spec.
pub const EI_MAG0: usize = 0;
pub const EI_MAG1: usize = 1;
pub const EI_MAG2: usize = 2;
pub const EI_MAG3: usize = 3;
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;

pub const ELFMAG0: u8 = 0x7F;
pub const ELFMAG1: u8 = b'E';
pub const ELFMAG2: u8 = b'L';
pub const ELFMAG3: u8 = b'F';

pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

/// `e_machine` values we recognise. Module kernel_abi check rejects
/// any module whose machine doesn't match the running kernel's arch.
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

// ── Section header types ─────────────────────────────────────────────

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_NOTE: u32 = 7;

// ── Section flags ────────────────────────────────────────────────────

pub const SHF_WRITE: u64 = 1 << 0;
pub const SHF_ALLOC: u64 = 1 << 1;
pub const SHF_EXECINSTR: u64 = 1 << 2;

/// Parsed Elf64 file header (decoded LE).
///
/// Linux equivalent: `Elf64_Ehdr` in `include/uapi/linux/elf.h`.
#[derive(Copy, Clone, Debug)]
pub struct Elf64Header {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// Parsed Elf64 section header.
#[derive(Copy, Clone, Debug)]
pub struct Elf64SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// Parsed Elf64 program header.
#[derive(Copy, Clone, Debug)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Errors raised by the ELF decoder.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// Buffer too short for the header offset implied.
    TooShort,
    /// ELF magic missing.
    BadMagic,
    /// Not ELFCLASS64.
    InvalidClass,
    /// Not ELFDATA2LSB.
    InvalidEndianness,
    /// e_version mismatch.
    InvalidVersion,
    /// Not ET_REL.
    InvalidType,
    /// `e_machine` not recognised.
    InvalidArch,
    /// Section/program-header offset or entsize out of bounds.
    BadOffset,
}

/// Parse the 64-byte ELF64 file header at offset 0.
///
/// Linux ref: `linux/kernel/module/main.c::elf_validity_cache_copy`
/// (`main.c:1788`) — same magic/class/endian/type/arch policy.
pub fn parse_header(bytes: &[u8]) -> Result<Elf64Header, HeaderError> {
    if bytes.len() < 64 {
        return Err(HeaderError::TooShort);
    }
    if bytes[EI_MAG0] != ELFMAG0
        || bytes[EI_MAG1] != ELFMAG1
        || bytes[EI_MAG2] != ELFMAG2
        || bytes[EI_MAG3] != ELFMAG3
    {
        return Err(HeaderError::BadMagic);
    }
    if bytes[EI_CLASS] != ELFCLASS64 {
        return Err(HeaderError::InvalidClass);
    }
    if bytes[EI_DATA] != ELFDATA2LSB {
        return Err(HeaderError::InvalidEndianness);
    }
    if bytes[EI_VERSION] != EV_CURRENT {
        return Err(HeaderError::InvalidVersion);
    }

    let e_type = read_u16(bytes, 0x10);
    let e_machine = read_u16(bytes, 0x12);
    let e_version = read_u32(bytes, 0x14);
    let e_entry = read_u64(bytes, 0x18);
    let e_phoff = read_u64(bytes, 0x20);
    let e_shoff = read_u64(bytes, 0x28);
    let e_flags = read_u32(bytes, 0x30);
    let e_ehsize = read_u16(bytes, 0x34);
    let e_phentsize = read_u16(bytes, 0x36);
    let e_phnum = read_u16(bytes, 0x38);
    let e_shentsize = read_u16(bytes, 0x3A);
    let e_shnum = read_u16(bytes, 0x3C);
    let e_shstrndx = read_u16(bytes, 0x3E);

    if e_type != ET_REL {
        return Err(HeaderError::InvalidType);
    }
    if e_machine != EM_X86_64 && e_machine != EM_AARCH64 {
        return Err(HeaderError::InvalidArch);
    }
    if e_shnum > 0 {
        let entsize = e_shentsize as usize;
        let count = e_shnum as usize;
        let off = e_shoff as usize;
        let end = off
            .checked_add(entsize.checked_mul(count).ok_or(HeaderError::BadOffset)?)
            .ok_or(HeaderError::BadOffset)?;
        if end > bytes.len() || entsize < 64 {
            return Err(HeaderError::BadOffset);
        }
    }
    Ok(Elf64Header {
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    })
}

/// Parse the section header at `idx`.
pub fn parse_section(
    bytes: &[u8],
    hdr: &Elf64Header,
    idx: usize,
) -> Result<Elf64SectionHeader, HeaderError> {
    let entsize = hdr.e_shentsize as usize;
    let off = hdr
        .e_shoff
        .checked_add(
            (idx as u64)
                .checked_mul(entsize as u64)
                .ok_or(HeaderError::BadOffset)?,
        )
        .ok_or(HeaderError::BadOffset)? as usize;
    if off + 64 > bytes.len() {
        return Err(HeaderError::BadOffset);
    }
    Ok(Elf64SectionHeader {
        sh_name: read_u32(bytes, off),
        sh_type: read_u32(bytes, off + 0x04),
        sh_flags: read_u64(bytes, off + 0x08),
        sh_addr: read_u64(bytes, off + 0x10),
        sh_offset: read_u64(bytes, off + 0x18),
        sh_size: read_u64(bytes, off + 0x20),
        sh_link: read_u32(bytes, off + 0x28),
        sh_info: read_u32(bytes, off + 0x2C),
        sh_addralign: read_u64(bytes, off + 0x30),
        sh_entsize: read_u64(bytes, off + 0x38),
    })
}

/// Resolve a section name from the `.shstrtab` section.
pub fn section_name<'a>(bytes: &'a [u8], hdr: &Elf64Header, shdr: &Elf64SectionHeader) -> &'a str {
    if hdr.e_shstrndx as usize >= hdr.e_shnum as usize {
        return "";
    }
    let strtab = match parse_section(bytes, hdr, hdr.e_shstrndx as usize) {
        Ok(s) => s,
        Err(_) => return "",
    };
    let off = strtab.sh_offset as usize + shdr.sh_name as usize;
    if off >= bytes.len() {
        return "";
    }
    let mut end = off;
    while end < bytes.len() && bytes[end] != 0 {
        end += 1;
    }
    core::str::from_utf8(&bytes[off..end]).unwrap_or("")
}

/// Resolve a string from an arbitrary string-table section.
pub fn string_in_table<'a>(bytes: &'a [u8], strtab: &Elf64SectionHeader, name_off: u32) -> &'a str {
    let off = strtab.sh_offset as usize + name_off as usize;
    if off >= bytes.len() {
        return "";
    }
    let mut end = off;
    while end < bytes.len() && bytes[end] != 0 {
        end += 1;
    }
    core::str::from_utf8(&bytes[off..end]).unwrap_or("")
}

#[inline]
pub(crate) fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().expect("len 2"))
}
#[inline]
pub(crate) fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("len 4"))
}
#[inline]
pub(crate) fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("len 8"))
}
