//! ELF64 parser.
//!
//! Spec: `userspace/specification/spec.md`. Turns a byte slice
//! holding an ELF64 executable into an `ExecImage` populated with
//! every `PT_LOAD` program header. Downstream the loader walks
//! `image.segments`, draws physical frames from the allocator, and
//! calls `AddressSpace::map_region` + `materialize` to install PTEs.
//!
//! Scope:
//! - `ET_EXEC` (static binaries) and `ET_DYN` (PIE / shared
//!   objects) both parse; loader's relocation pass is Stage-4+.
//! - Little-endian only (matches both x86_64 and aarch64 targets).
//! - Recognises the `PT_INTERP` header and stores the interpreter
//!   path so the dynamic-linker entry point can be located later.
//! - Rejects 32-bit ELFs, non-ELF magic, and byte slices too short
//!   for the declared header offsets.
//!
//! Not covered yet (Stage-4+):
//! - Section-header walk (we only need program headers for load).
//! - `PT_NOTE` / `PT_GNU_STACK` handling.
//! - Relocation entries from `DT_REL` / `DT_RELA`.
//!
//! `PT_TLS` is parsed into `image.tls` (a `TlsTemplate`); the
//! actual per-thread-block staging + `IA32_FS_BASE` programming
//! still belongs to a follow-up round (parse-only here).

use alloc::string::String;
use alloc::vec::Vec;

use crate::{DynEntry, ExecImage, ExecKind, Segment, SegmentFlags, TlsTemplate};

// ── Wire constants (ELF spec) ───────────────────────────────────────

const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474e551;

const PF_X: u32 = 1 << 0;
const PF_W: u32 = 1 << 1;
const PF_R: u32 = 1 << 2;

// ── Errors ──────────────────────────────────────────────────────────

/// Errors raised during `parse`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    BadType,
    BadPhoff,
    InterpOutOfBounds,
    /// PT_DYNAMIC's file region (p_offset .. p_offset+p_filesz) lies
    /// outside the input bytes or has a length that isn't a multiple
    /// of `sizeof(Elf64_Dyn) == 16`.
    DynamicOutOfBounds,
    /// PT_TLS file region lies outside the input bytes, mem_size <
    /// file_size, or the alignment isn't a power of two.
    TlsOutOfBounds,
    /// More than one PT_TLS segment was present. The SysV ABI allows
    /// only one TLS template per ELF — the dynamic loader's IE-model
    /// thread-pointer arithmetic assumes a single contiguous block.
    MultiplePtTls,
}

// ── Parser ──────────────────────────────────────────────────────────

/// Parse an ELF64 little-endian executable into an `ExecImage`.
/// `argv` / `envp` / `aux` on the returned image are left empty —
/// the caller fills those in before handing the image to the
/// loader.
pub fn parse(bytes: &[u8]) -> Result<ExecImage, ElfError> {
    if bytes.len() < 64 {
        return Err(ElfError::TooShort);
    }

    // ELF header identification.
    if bytes[EI_MAG0] != 0x7F
        || bytes[EI_MAG1] != b'E'
        || bytes[EI_MAG2] != b'L'
        || bytes[EI_MAG3] != b'F'
    {
        return Err(ElfError::BadMagic);
    }
    if bytes[EI_CLASS] != ELFCLASS64 {
        return Err(ElfError::Not64Bit);
    }
    if bytes[EI_DATA] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }

    let e_type = read_u16(bytes, 0x10);
    let kind = match e_type {
        ET_EXEC => ExecKind::Elf64Exec,
        ET_DYN => ExecKind::Elf64Dyn,
        _ => return Err(ElfError::BadType),
    };

    let e_entry = read_u64(bytes, 0x18);
    let e_phoff = read_u64(bytes, 0x20);
    let e_phentsize = read_u16(bytes, 0x36);
    let e_phnum = read_u16(bytes, 0x38);

    let phoff = e_phoff as usize;
    let entsize = e_phentsize as usize;
    let phnum = e_phnum as usize;

    if phnum > 0 {
        let ph_table_end = phoff
            .checked_add(entsize.checked_mul(phnum).ok_or(ElfError::BadPhoff)?)
            .ok_or(ElfError::BadPhoff)?;
        if ph_table_end > bytes.len() || entsize < 56 {
            return Err(ElfError::BadPhoff);
        }
    }

    let mut segments = Vec::new();
    let mut interp: Option<String> = None;
    let mut dynamic: Vec<DynEntry> = Vec::new();
    let mut tls: Option<TlsTemplate> = None;
    let mut stack_flags: Option<SegmentFlags> = None;

    for i in 0..phnum {
        let off = phoff + i * entsize;
        let p_type = read_u32(bytes, off);
        let p_flags = read_u32(bytes, off + 0x04);
        let p_offset = read_u64(bytes, off + 0x08);
        let p_vaddr = read_u64(bytes, off + 0x10);
        let p_filesz = read_u64(bytes, off + 0x20);
        let p_memsz = read_u64(bytes, off + 0x28);

        match p_type {
            PT_LOAD => {
                let mut flags = SegmentFlags::default();
                if p_flags & PF_R != 0 {
                    flags = flags | SegmentFlags::READ;
                }
                if p_flags & PF_W != 0 {
                    flags = flags | SegmentFlags::WRITE;
                }
                if p_flags & PF_X != 0 {
                    flags = flags | SegmentFlags::EXEC;
                }
                segments.push(Segment {
                    vaddr: p_vaddr,
                    file_off: p_offset,
                    file_size: p_filesz,
                    mem_size: p_memsz,
                    flags,
                });
            }
            PT_DYNAMIC => {
                // Walk the array of `Elf64_Dyn { d_tag: i64, d_val: u64 }`
                // entries (16 bytes each). The terminator is DT_NULL (0).
                // We capture every tag here verbatim so the loader
                // (which knows which DT_* it cares about) can match
                // against a flat list rather than re-parsing.
                let start = p_offset as usize;
                let end = start
                    .checked_add(p_filesz as usize)
                    .ok_or(ElfError::DynamicOutOfBounds)?;
                if end > bytes.len() {
                    return Err(ElfError::DynamicOutOfBounds);
                }
                if (end - start) % 16 != 0 {
                    return Err(ElfError::DynamicOutOfBounds);
                }
                let mut cur = start;
                while cur + 16 <= end {
                    let tag = read_i64(bytes, cur);
                    let val = read_u64(bytes, cur + 8);
                    cur += 16;
                    if tag == 0 {
                        break;
                    } // DT_NULL terminator.
                    dynamic.push(DynEntry { tag, val });
                }
            }
            PT_TLS => {
                // SysV ABI permits at most one PT_TLS. Reject extras
                // outright rather than silently overwriting — a binary
                // with two TLS templates is malformed and the IE-model
                // offsets would be ambiguous.
                if tls.is_some() {
                    return Err(ElfError::MultiplePtTls);
                }
                let p_align = read_u64(bytes, off + 0x30);
                // Spec: p_align == 0 or 1 means "no alignment
                // requirement" — normalise to 1 so callers can rely on
                // the field being a non-zero power of two.
                let align = if p_align == 0 { 1 } else { p_align };
                if !align.is_power_of_two() {
                    return Err(ElfError::TlsOutOfBounds);
                }
                if p_memsz < p_filesz {
                    return Err(ElfError::TlsOutOfBounds);
                }
                let end = (p_offset as usize)
                    .checked_add(p_filesz as usize)
                    .ok_or(ElfError::TlsOutOfBounds)?;
                if end > bytes.len() {
                    return Err(ElfError::TlsOutOfBounds);
                }
                tls = Some(TlsTemplate {
                    file_off: p_offset,
                    file_size: p_filesz,
                    mem_size: p_memsz,
                    align,
                    vaddr: p_vaddr,
                });
            }
            PT_INTERP => {
                let start = p_offset as usize;
                let end = start
                    .checked_add(p_filesz as usize)
                    .ok_or(ElfError::InterpOutOfBounds)?;
                if end > bytes.len() {
                    return Err(ElfError::InterpOutOfBounds);
                }
                // Trim trailing NUL.
                let raw = &bytes[start..end];
                let trimmed = match raw.iter().position(|&b| b == 0) {
                    Some(n) => &raw[..n],
                    None => raw,
                };
                interp = core::str::from_utf8(trimmed).ok().map(String::from);
            }
            PT_GNU_STACK => {
                let mut flags = SegmentFlags::default();
                if p_flags & PF_R != 0 {
                    flags = flags | SegmentFlags::READ;
                }
                if p_flags & PF_W != 0 {
                    flags = flags | SegmentFlags::WRITE;
                }
                if p_flags & PF_X != 0 {
                    flags = flags | SegmentFlags::EXEC;
                }
                stack_flags = Some(flags);
            }
            PT_NOTE => {
                // Not fully implemented, just parsed.
            }
            _ => { /* other PT_* ignored at this tier */ }
        }
    }

    Ok(ExecImage {
        kind,
        entry: e_entry,
        interp,
        segments,
        dynamic,
        tls,
        stack_flags,
        argv: Vec::new(),
        envp: Vec::new(),
        aux: Vec::new(),
    })
}

// ── Little-endian readers ───────────────────────────────────────────

#[inline]
fn read_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

#[inline]
fn read_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

#[inline]
fn read_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

#[inline]
fn read_i64(bytes: &[u8], off: usize) -> i64 {
    i64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}
