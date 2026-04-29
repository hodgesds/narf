//! PE32+ image parser.
//!
//! Parses just enough of the Microsoft *PE Format* spec to drive the
//! M0 loader: DOS header → NT headers → optional header (PE32+ only,
//! PE32 rejected) → section table → import directory → base reloc
//! directory.
//!
//! Strict reads only — every offset is bounds-checked against the
//! input slice, every RVA is translated through the section table,
//! and any pattern that would let a malformed image escape into
//! the loader's address space is rejected here. See
//! `compat/win/specification/spec.md` §4 for the full invariant set.

use alloc::string::String;
use alloc::vec::Vec;

// ── format constants ──────────────────────────────────────────────

const DOS_SIG: u16 = 0x5A4D; // 'MZ'
const PE_SIG:  u32 = 0x0000_4550; // 'PE\0\0'

const OPT_MAGIC_PE32_PLUS: u16 = 0x20B;
const OPT_MAGIC_PE32:      u16 = 0x10B;

const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_ARM64: u16 = 0xAA64;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_WRITE:   u32 = 0x8000_0000;

const DIR_IMPORT:    usize = 1;
const DIR_BASERELOC: usize = 5;

const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64:    u16 = 10;

// ── public types ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct PeImage<'a> {
    pub bytes:      &'a [u8],
    pub machine:    Machine,
    pub entry:      u64,
    pub image_base: u64,
    pub size_of_image: u32,
    pub sections:   Vec<Section>,
    pub imports:    Vec<Import>,
    pub relocs:     Vec<BaseReloc>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Machine {
    Amd64,
    Arm64,
}

#[derive(Debug)]
pub struct Section {
    pub name:        [u8; 8],
    pub virt_addr:   u32,
    pub virt_size:   u32,
    pub raw_offset:  u32,
    pub raw_size:    u32,
    pub characteristics: u32,
}

#[derive(Debug)]
pub struct Import {
    pub module:  String,
    pub symbol:  String,
    pub iat_rva: u32,
}

#[derive(Debug)]
pub struct BaseReloc {
    pub rva:  u32,
    pub kind: BaseRelocKind,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BaseRelocKind {
    Dir64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeError {
    TooSmall,
    BadDosSignature,
    BadPeSignature,
    UnsupportedOptionalHeader,
    UnsupportedMachine,
    WritableExecutableSection,
    BadSection,
    BadImport,
    BadReloc,
    NotImplemented,
}

// ── byte-slice accessors (all bounds-checked, no unsafe) ──────────

#[inline]
fn read_u16(bytes: &[u8], off: usize) -> Result<u16, PeError> {
    bytes.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(PeError::TooSmall)
}

#[inline]
fn read_u32(bytes: &[u8], off: usize) -> Result<u32, PeError> {
    bytes.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(PeError::TooSmall)
}

#[inline]
fn read_u64(bytes: &[u8], off: usize) -> Result<u64, PeError> {
    bytes.get(off..off + 8)
        .map(|s| u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
        .ok_or(PeError::TooSmall)
}

/// Read a NUL-terminated ASCII C string starting at `off`. Caps the
/// search at 256 bytes so a malformed image cannot trick us into a
/// long scan. Returned string is lowercased — Win32 imports are
/// case-insensitive and we canonicalise on parse.
fn read_cstr_lower(bytes: &[u8], off: usize, err: PeError) -> Result<String, PeError> {
    const CAP: usize = 256;
    let end = (off + CAP).min(bytes.len());
    let slice = bytes.get(off..end).ok_or(err)?;
    let nul = slice.iter().position(|&b| b == 0).ok_or(err)?;
    let raw = &slice[..nul];
    if !raw.iter().all(|&b| b.is_ascii()) {
        return Err(err);
    }
    let mut s = String::with_capacity(raw.len());
    for &b in raw {
        s.push(b.to_ascii_lowercase() as char);
    }
    Ok(s)
}

/// Translate an RVA into a file offset using the section table.
/// RVAs are valid only within `[virt_addr, virt_addr + virt_size)`
/// of some section that has `raw_size` bytes on disk.
fn rva_to_file(sections: &[Section], rva: u32) -> Option<usize> {
    for s in sections {
        let start = s.virt_addr;
        let end = s.virt_addr.checked_add(s.virt_size)?;
        if rva >= start && rva < end {
            let delta = rva - start;
            // RVA must also land within the on-disk slice — sections
            // can have virt_size > raw_size (BSS-like padding), and
            // referencing those bytes in a file-resident structure
            // (import, name) is malformed.
            if delta >= s.raw_size {
                return None;
            }
            return Some(s.raw_offset as usize + delta as usize);
        }
    }
    None
}

// ── top-level parser ──────────────────────────────────────────────

pub fn parse(bytes: &[u8]) -> Result<PeImage<'_>, PeError> {
    // 1. DOS header.
    if bytes.len() < 0x40 {
        return Err(PeError::TooSmall);
    }
    if read_u16(bytes, 0)? != DOS_SIG {
        return Err(PeError::BadDosSignature);
    }
    let nt_off = read_u32(bytes, 0x3C)? as usize;

    // 2. NT signature + file header.
    if read_u32(bytes, nt_off)? != PE_SIG {
        return Err(PeError::BadPeSignature);
    }
    let fh_off = nt_off + 4;
    if bytes.len() < fh_off + 20 {
        return Err(PeError::TooSmall);
    }
    let machine_raw = read_u16(bytes, fh_off)?;
    let machine = match machine_raw {
        MACHINE_AMD64 => Machine::Amd64,
        MACHINE_ARM64 => Machine::Arm64,
        _             => return Err(PeError::UnsupportedMachine),
    };
    let num_sections   = read_u16(bytes, fh_off + 2)? as usize;
    let opt_hdr_size   = read_u16(bytes, fh_off + 16)? as usize;

    // 3. Optional header — PE32+ only.
    let oh_off = fh_off + 20;
    if bytes.len() < oh_off + opt_hdr_size {
        return Err(PeError::TooSmall);
    }
    let opt_magic = read_u16(bytes, oh_off)?;
    if opt_magic == OPT_MAGIC_PE32 || opt_magic != OPT_MAGIC_PE32_PLUS {
        return Err(PeError::UnsupportedOptionalHeader);
    }

    let entry         = read_u32(bytes, oh_off + 0x10)? as u64;
    let image_base    = read_u64(bytes, oh_off + 0x18)?;
    let size_of_image = read_u32(bytes, oh_off + 0x38)?;
    let num_dirs      = read_u32(bytes, oh_off + 0x6C)? as usize;
    let dir_off       = oh_off + 0x70;

    if num_dirs > 16 {
        // Spec maxes out at 16 standard directories; reject obvious
        // garbage so the loop below has a sane bound.
        return Err(PeError::UnsupportedOptionalHeader);
    }
    if bytes.len() < dir_off + num_dirs * 8 {
        return Err(PeError::TooSmall);
    }
    let read_dir = |idx: usize| -> Option<(u32, u32)> {
        if idx >= num_dirs { return None; }
        let off = dir_off + idx * 8;
        let rva  = read_u32(bytes, off).ok()?;
        let size = read_u32(bytes, off + 4).ok()?;
        if rva == 0 || size == 0 { None } else { Some((rva, size)) }
    };

    // 4. Section table.
    let sec_off = oh_off + opt_hdr_size;
    if bytes.len() < sec_off + num_sections * 40 {
        return Err(PeError::TooSmall);
    }
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_off + i * 40;
        let mut name = [0u8; 8];
        name.copy_from_slice(&bytes[s..s + 8]);
        let virt_size  = read_u32(bytes, s + 8)?;
        let virt_addr  = read_u32(bytes, s + 12)?;
        let raw_size   = read_u32(bytes, s + 16)?;
        let raw_offset = read_u32(bytes, s + 20)?;
        let chars      = read_u32(bytes, s + 36)?;

        // W^X: see spec §4. Refuse the malware-fingerprint pattern.
        if (chars & SCN_MEM_WRITE) != 0 && (chars & SCN_MEM_EXECUTE) != 0 {
            return Err(PeError::WritableExecutableSection);
        }
        // Bounds: raw bytes must fit inside the file.
        let raw_end = (raw_offset as usize).checked_add(raw_size as usize)
            .ok_or(PeError::BadSection)?;
        if raw_size != 0 && raw_end > bytes.len() {
            return Err(PeError::BadSection);
        }
        // Bounds: virt_addr + virt_size must not overflow.
        virt_addr.checked_add(virt_size).ok_or(PeError::BadSection)?;

        sections.push(Section {
            name, virt_addr, virt_size, raw_offset, raw_size,
            characteristics: chars,
        });
    }

    // 5. Imports.
    let imports = if let Some((rva, _size)) = read_dir(DIR_IMPORT) {
        parse_imports(bytes, &sections, rva)?
    } else {
        Vec::new()
    };

    // 6. Base relocations.
    let relocs = if let Some((rva, size)) = read_dir(DIR_BASERELOC) {
        parse_relocs(bytes, &sections, rva, size)?
    } else {
        Vec::new()
    };

    Ok(PeImage {
        bytes, machine, entry, image_base, size_of_image,
        sections, imports, relocs,
    })
}

// ── import directory ──────────────────────────────────────────────

fn parse_imports(
    bytes: &[u8],
    sections: &[Section],
    dir_rva: u32,
) -> Result<Vec<Import>, PeError> {
    let mut out = Vec::new();
    let mut cursor = rva_to_file(sections, dir_rva).ok_or(PeError::BadImport)?;
    loop {
        if bytes.len() < cursor + 20 {
            return Err(PeError::BadImport);
        }
        let ilt_rva    = read_u32(bytes, cursor)?;
        let name_rva   = read_u32(bytes, cursor + 12)?;
        let iat_rva    = read_u32(bytes, cursor + 16)?;
        // All-zero descriptor terminates.
        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }
        if name_rva == 0 || iat_rva == 0 {
            return Err(PeError::BadImport);
        }
        let name_off = rva_to_file(sections, name_rva).ok_or(PeError::BadImport)?;
        let module = read_cstr_lower(bytes, name_off, PeError::BadImport)?;

        // Walk the lookup table. Prefer ILT (OriginalFirstThunk) — bound
        // imports overwrite the IAT but leave the ILT pristine. If the
        // ILT is absent we fall back to the IAT, which is valid for
        // not-yet-resolved images.
        let lookup_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let mut walk = rva_to_file(sections, lookup_rva).ok_or(PeError::BadImport)?;
        let mut iat_slot = iat_rva;
        loop {
            let entry = read_u64(bytes, walk)?;
            if entry == 0 {
                break;
            }
            let symbol = if entry & (1u64 << 63) != 0 {
                // Ordinal import. Render as `#NNN` so the dispatcher
                // can look it up against a per-module ordinal table.
                let ord = entry as u16;
                let mut s = String::from("#");
                let mut digits = [0u8; 5];
                let mut n = ord;
                let mut i = 0;
                if n == 0 {
                    s.push('0');
                } else {
                    while n > 0 {
                        digits[i] = b'0' + (n % 10) as u8;
                        n /= 10;
                        i += 1;
                    }
                    while i > 0 {
                        i -= 1;
                        s.push(digits[i] as char);
                    }
                }
                s
            } else {
                let by_name_rva = (entry & 0x7FFF_FFFF) as u32;
                let by_name_off = rva_to_file(sections, by_name_rva)
                    .ok_or(PeError::BadImport)?;
                // IMAGE_IMPORT_BY_NAME = { Hint: u16; Name: cstring }.
                read_cstr_lower(bytes, by_name_off + 2, PeError::BadImport)?
            };
            out.push(Import {
                module: module.clone(),
                symbol,
                iat_rva: iat_slot,
            });
            walk += 8;
            iat_slot = iat_slot.checked_add(8).ok_or(PeError::BadImport)?;
        }
        cursor += 20;
    }
    Ok(out)
}

// ── base relocations ──────────────────────────────────────────────

fn parse_relocs(
    bytes: &[u8],
    _sections: &[Section],
    dir_rva: u32,
    dir_size: u32,
) -> Result<Vec<BaseReloc>, PeError> {
    let mut out = Vec::new();
    let mut cursor = rva_to_file(_sections, dir_rva).ok_or(PeError::BadReloc)?;
    let end = cursor.checked_add(dir_size as usize).ok_or(PeError::BadReloc)?;
    if bytes.len() < end {
        return Err(PeError::BadReloc);
    }
    while cursor < end {
        if cursor + 8 > end {
            return Err(PeError::BadReloc);
        }
        let page_rva   = read_u32(bytes, cursor)?;
        let block_size = read_u32(bytes, cursor + 4)? as usize;
        if block_size < 8 || cursor + block_size > end {
            return Err(PeError::BadReloc);
        }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let raw = read_u16(bytes, cursor + 8 + i * 2)?;
            let typ = raw >> 12;
            let off = (raw & 0x0FFF) as u32;
            match typ {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Padding so the block aligns to 4 bytes — skip.
                }
                IMAGE_REL_BASED_DIR64 => {
                    let rva = page_rva.checked_add(off).ok_or(PeError::BadReloc)?;
                    out.push(BaseReloc { rva, kind: BaseRelocKind::Dir64 });
                }
                _ => {
                    // Spec lists ten more reloc kinds; none are emitted
                    // by current toolchains for AMD64/ARM64 PE32+
                    // output. Refuse rather than ignore — a foreign
                    // reloc kind means we don't understand the image.
                    return Err(PeError::BadReloc);
                }
            }
        }
        cursor += block_size;
    }
    Ok(out)
}

// ── tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;
    use super::*;

    /// Minimum-viable PE32+ AMD64 image. One `.text` section
    /// (R+X), one `.idata` (R only) holding the import dir + name
    /// "kernel32.dll" + ILT/IAT pointing at "ExitProcess", and one
    /// base-reloc block with a single DIR64 entry.
    ///
    /// The blob is tiny on purpose — it exercises every path
    /// `parse` cares about without any toolchain-specific glue.
    fn make_min_pe(machine: u16, mut mutate: impl FnMut(&mut [u8])) -> Vec<u8> {
        let mut buf = vec![0u8; 0x800];

        // DOS header.
        buf[0..2].copy_from_slice(&DOS_SIG.to_le_bytes());
        let nt_off: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&nt_off.to_le_bytes());

        // NT signature.
        buf[0x80..0x84].copy_from_slice(&PE_SIG.to_le_bytes());
        // File header.
        let fh = 0x84;
        buf[fh..fh + 2].copy_from_slice(&machine.to_le_bytes());
        buf[fh + 2..fh + 4].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        let opt_size: u16 = 0xF0;
        buf[fh + 16..fh + 18].copy_from_slice(&opt_size.to_le_bytes());

        // Optional header (PE32+).
        let oh = fh + 20; // 0x98
        buf[oh..oh + 2].copy_from_slice(&OPT_MAGIC_PE32_PLUS.to_le_bytes());
        // AddressOfEntryPoint @ +0x10.
        buf[oh + 0x10..oh + 0x14].copy_from_slice(&0x1000u32.to_le_bytes());
        // ImageBase @ +0x18.
        buf[oh + 0x18..oh + 0x20].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        // SizeOfImage @ +0x38.
        buf[oh + 0x38..oh + 0x3C].copy_from_slice(&0x3000u32.to_le_bytes());
        // NumberOfRvaAndSizes @ +0x6C.
        buf[oh + 0x6C..oh + 0x70].copy_from_slice(&16u32.to_le_bytes());
        // DataDirectory[1] = Import: RVA 0x2000, size 0x60.
        buf[oh + 0x70 + 1 * 8..oh + 0x70 + 1 * 8 + 4]
            .copy_from_slice(&0x2000u32.to_le_bytes());
        buf[oh + 0x70 + 1 * 8 + 4..oh + 0x70 + 1 * 8 + 8]
            .copy_from_slice(&0x60u32.to_le_bytes());
        // DataDirectory[5] = BaseReloc: RVA 0x2100, size 0x10.
        buf[oh + 0x70 + 5 * 8..oh + 0x70 + 5 * 8 + 4]
            .copy_from_slice(&0x2100u32.to_le_bytes());
        buf[oh + 0x70 + 5 * 8 + 4..oh + 0x70 + 5 * 8 + 8]
            .copy_from_slice(&0x10u32.to_le_bytes());

        // Section table.
        let sec = oh + opt_size as usize; // 0x188
        // .text — RVA 0x1000, size 0x100, raw at 0x400, R+X.
        buf[sec..sec + 5].copy_from_slice(b".text");
        buf[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // virt_size
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virt_addr
        buf[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes()); // raw_size
        buf[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw_offset
        buf[sec + 36..sec + 40]
            .copy_from_slice(&(SCN_MEM_EXECUTE | 0x4000_0000).to_le_bytes());
        // .idata — RVA 0x2000, size 0x300, raw at 0x500, R only.
        let s2 = sec + 40;
        buf[s2..s2 + 6].copy_from_slice(b".idata");
        buf[s2 + 8..s2 + 12].copy_from_slice(&0x300u32.to_le_bytes());
        buf[s2 + 12..s2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[s2 + 16..s2 + 20].copy_from_slice(&0x300u32.to_le_bytes());
        buf[s2 + 20..s2 + 24].copy_from_slice(&0x500u32.to_le_bytes());
        buf[s2 + 36..s2 + 40].copy_from_slice(&0x4000_0000u32.to_le_bytes());

        // Import directory at file offset 0x500 (RVA 0x2000).
        // IID #0: ILT 0x2040, Name 0x2080, IAT 0x20A0.
        let iid = 0x500;
        buf[iid..iid + 4].copy_from_slice(&0x2040u32.to_le_bytes()); // ILT
        buf[iid + 12..iid + 16].copy_from_slice(&0x2080u32.to_le_bytes()); // Name
        buf[iid + 16..iid + 20].copy_from_slice(&0x20A0u32.to_le_bytes()); // IAT
        // IID #1: terminator (all zero — buf already zero).

        // ILT @ file 0x540 (RVA 0x2040): one entry → IMAGE_IMPORT_BY_NAME @ 0x20C0.
        let ilt = 0x540;
        buf[ilt..ilt + 8].copy_from_slice(&0x20C0u64.to_le_bytes());
        // (next entry is zero terminator)

        // IAT @ file 0x5A0 (RVA 0x20A0): same entry pre-resolution.
        let iat = 0x5A0;
        buf[iat..iat + 8].copy_from_slice(&0x20C0u64.to_le_bytes());

        // Module name @ file 0x580 (RVA 0x2080): "kernel32.dll\0".
        let modname = 0x580;
        buf[modname..modname + 12].copy_from_slice(b"kernel32.dll");
        // (NUL already there)

        // IMAGE_IMPORT_BY_NAME @ file 0x5C0 (RVA 0x20C0): hint=0, name="ExitProcess".
        let ibn = 0x5C0;
        buf[ibn..ibn + 2].copy_from_slice(&0u16.to_le_bytes()); // hint
        buf[ibn + 2..ibn + 13].copy_from_slice(b"ExitProcess");

        // Base reloc block @ file 0x600 (RVA 0x2100): page 0x1000, size 0x10,
        // one DIR64 reloc at offset 0x008.
        let br = 0x600;
        buf[br..br + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // page rva
        buf[br + 4..br + 8].copy_from_slice(&0x10u32.to_le_bytes()); // block size
        let entry: u16 = (IMAGE_REL_BASED_DIR64 << 12) | 0x008;
        buf[br + 8..br + 10].copy_from_slice(&entry.to_le_bytes());
        // entry[1] = ABSOLUTE padding (zero already).

        mutate(&mut buf);
        buf
    }

    #[test]
    fn parses_minimal_amd64() {
        let buf = make_min_pe(MACHINE_AMD64, |_| {});
        let img = parse(&buf).expect("parse");
        assert_eq!(img.machine, Machine::Amd64);
        assert_eq!(img.entry, 0x1000);
        assert_eq!(img.image_base, 0x1_4000_0000);
        assert_eq!(img.sections.len(), 2);
        assert_eq!(img.imports.len(), 1);
        assert_eq!(img.imports[0].module, "kernel32.dll");
        assert_eq!(img.imports[0].symbol, "exitprocess");
        assert_eq!(img.imports[0].iat_rva, 0x20A0);
        assert_eq!(img.relocs.len(), 1);
        assert_eq!(img.relocs[0].rva, 0x1008);
        assert_eq!(img.relocs[0].kind, BaseRelocKind::Dir64);
    }

    #[test]
    fn parses_minimal_arm64() {
        let buf = make_min_pe(MACHINE_ARM64, |_| {});
        let img = parse(&buf).expect("parse");
        assert_eq!(img.machine, Machine::Arm64);
    }

    #[test]
    fn rejects_bad_dos_sig() {
        let buf = make_min_pe(MACHINE_AMD64, |b| { b[0] = 0; b[1] = 0; });
        assert_eq!(parse(&buf).unwrap_err(), PeError::BadDosSignature);
    }

    #[test]
    fn rejects_bad_pe_sig() {
        let buf = make_min_pe(MACHINE_AMD64, |b| { b[0x80] = 0; });
        assert_eq!(parse(&buf).unwrap_err(), PeError::BadPeSignature);
    }

    #[test]
    fn rejects_pe32() {
        // Optional header magic = 0x10B (PE32 i386, not PE32+).
        let buf = make_min_pe(MACHINE_AMD64, |b| {
            b[0x98..0x9A].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        });
        assert_eq!(parse(&buf).unwrap_err(), PeError::UnsupportedOptionalHeader);
    }

    #[test]
    fn rejects_unsupported_machine() {
        // i386 = 0x14C — not in our supported set.
        let buf = make_min_pe(0x014C, |_| {});
        assert_eq!(parse(&buf).unwrap_err(), PeError::UnsupportedMachine);
    }

    #[test]
    fn rejects_writable_executable_section() {
        // .text was R+X (chars = 0x6000_0000); add MEM_WRITE to make
        // it the malware-fingerprint W+X. The .text characteristics
        // field is at section-table-offset 36; section table starts at
        // oh + opt_size = 0x98 + 0xF0 = 0x188. So .text chars at 0x1AC.
        let buf = make_min_pe(MACHINE_AMD64, |b| {
            let chars_off = 0x188 + 36;
            let chars = u32::from_le_bytes(b[chars_off..chars_off + 4].try_into().unwrap());
            let new = chars | SCN_MEM_WRITE;
            b[chars_off..chars_off + 4].copy_from_slice(&new.to_le_bytes());
        });
        assert_eq!(parse(&buf).unwrap_err(), PeError::WritableExecutableSection);
    }

    #[test]
    fn rejects_section_oob_raw() {
        // Push .text raw_offset past EOF.
        let buf = make_min_pe(MACHINE_AMD64, |b| {
            let raw_off_off = 0x188 + 20;
            b[raw_off_off..raw_off_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        });
        assert_eq!(parse(&buf).unwrap_err(), PeError::BadSection);
    }

    #[test]
    fn rejects_import_with_invalid_name_rva() {
        // Point IID#0.Name at an RVA outside any section.
        let buf = make_min_pe(MACHINE_AMD64, |b| {
            let iid_name = 0x500 + 12;
            b[iid_name..iid_name + 4].copy_from_slice(&0x9_0000u32.to_le_bytes());
        });
        assert_eq!(parse(&buf).unwrap_err(), PeError::BadImport);
    }

    #[test]
    fn rejects_unknown_reloc_kind() {
        // Replace the DIR64 entry with an unknown reloc type (0xF).
        let buf = make_min_pe(MACHINE_AMD64, |b| {
            let br_entry = 0x600 + 8;
            let entry: u16 = (0xF << 12) | 0x008;
            b[br_entry..br_entry + 2].copy_from_slice(&entry.to_le_bytes());
        });
        assert_eq!(parse(&buf).unwrap_err(), PeError::BadReloc);
    }
}
