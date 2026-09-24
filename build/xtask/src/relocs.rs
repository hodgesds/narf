//! Kernel relocation-table extraction for KASLR.
//!
//! The kernel is linked at a fixed virtual address with
//! `relocation-model=static`, so its absolute addresses are baked in. To slide
//! the image at boot we keep the linker's relocation records (`--emit-relocs`)
//! and recover them here, exactly as Linux does with `arch/x86/tools/relocs.c`
//! — and for the same reason it does not simply build PIC: the 32-bit entry in
//! `boot.S` needs absolute `R_X86_64_32` relocations that a PIC link rejects.
//!
//! ## What gets slid, and what must not
//!
//! Only relocations whose target section lives in the kernel half move. The
//! first LOAD segment is the identity-mapped boot stub at `0x100_0000`: its
//! absolute references are physical addresses that the kernel-half slide does
//! not affect, and adding the delta to them would corrupt the entry path.
//! Selection is therefore by `sh_addr`, not by section name.
//!
//! ## Why two lists
//!
//! `R_X86_64_64` patches a full 64-bit word. `R_X86_64_32S` patches a 32-bit
//! sign-extended field — what `code-model=kernel` emits — which can only
//! address the top 2 GiB. That is the hard cap on how far the image may slide,
//! and the apply pass has to know which width it is writing.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// `SHT_RELA`.
const SHT_RELA: u32 = 4;
/// `SHF_ALLOC` — the section is part of the loaded image.
const SHF_ALLOC: u64 = 0x2;

const R_X86_64_64: u32 = 1;
const R_X86_64_32: u32 = 10;
const R_X86_64_32S: u32 = 11;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;

/// Kernel-half base. Sections at or above this slide; the identity-mapped
/// boot stub below it does not.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Relocation sites to patch, split by the width of the field each one writes.
#[derive(Debug, Default)]
pub struct RelocTable {
    /// Virtual addresses of 64-bit absolute fields.
    pub abs64: Vec<u64>,
    /// Virtual addresses of 32-bit sign-extended absolute fields.
    pub abs32s: Vec<u64>,
    /// 32-bit PC-relative fields whose TARGET moves but whose own location
    /// does not — the identity-mapped boot stub referring into the kernel
    /// half. The displacement has to grow by the same delta.
    ///
    /// These are easy to miss: a PC-relative relocation is slide-invariant
    /// only when source and target move together. `boot.S`'s
    /// `call _start_rust` is one of them, and it reaches the kernel half only
    /// by 64-bit wraparound of a truncated `rel32`, so getting it wrong sends
    /// the first call into nothing.
    pub pcrel32_into_kernel: Vec<u64>,
}

impl RelocTable {
    pub fn total(&self) -> usize {
        self.abs64.len() + self.abs32s.len() + self.pcrel32_into_kernel.len()
    }

    /// Encoded size in bytes: a header plus one `u32` per site.
    ///
    /// Kernel-half offsets are stored relative to [`KERNEL_VIRT_BASE`]; the
    /// cross-half entries are physical/identity addresses below 4 GiB and are
    /// stored as-is. Either way four bytes is enough.
    pub fn encoded_len(&self) -> usize {
        20 + self.total() * 4
    }

    /// Encode for the boot-time apply pass. Little-endian throughout, as the
    /// only consumers are x86_64 and aarch64.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&RELOC_MAGIC.to_le_bytes());
        out.extend_from_slice(&(self.abs64.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.abs32s.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.pcrel32_into_kernel.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        for list in [&self.abs64, &self.abs32s] {
            for va in list {
                out.extend_from_slice(&((va - KERNEL_VIRT_BASE) as u32).to_le_bytes());
            }
        }
        // Already physical: the boot stub is identity-mapped.
        for pa in &self.pcrel32_into_kernel {
            out.extend_from_slice(&(*pa as u32).to_le_bytes());
        }
        out
    }
}

/// Header magic, so the apply pass can refuse a table that was never filled in
/// rather than sliding by garbage.
pub const RELOC_MAGIC: u32 = 0x4B41_534C; // "KASL"

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Parse a linked kernel ELF and collect every relocation the slide must
/// patch.
pub fn extract(elf_path: &Path) -> Result<RelocTable> {
    let bytes = std::fs::read(elf_path)
        .with_context(|| format!("reading kernel ELF {}", elf_path.display()))?;
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 {
        bail!("{} is not an ELF64 image", elf_path.display());
    }

    let shoff = u64_at(&bytes, 0x28) as usize;
    let shentsize = u16_at(&bytes, 0x3A) as usize;
    let shnum = u16_at(&bytes, 0x3C) as usize;
    if shoff == 0 || shnum == 0 {
        bail!("{} has no section headers", elf_path.display());
    }

    // (sh_addr, sh_flags) per section, for deciding whether a relocation's
    // target moves with the kernel half.
    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        sections.push((
            u32_at(&bytes, sh + 0x04), // sh_type
            u64_at(&bytes, sh + 0x08), // sh_flags
            u64_at(&bytes, sh + 0x10), // sh_addr
            u64_at(&bytes, sh + 0x18), // sh_offset
            u64_at(&bytes, sh + 0x20), // sh_size
            u32_at(&bytes, sh + 0x28), // sh_link
            u32_at(&bytes, sh + 0x2C), // sh_info
            u64_at(&bytes, sh + 0x38), // sh_entsize
        ));
    }

    // Symbol values, for resolving what each relocation POINTS AT. A
    // relocation's own section decides whether the patched field moves; the
    // symbol decides whether the value being encoded moves. Both matter, and
    // they differ exactly where the boot stub reaches into the kernel half.
    let symtab = symbol_values(&bytes, &sections)?;

    let mut table = RelocTable::default();
    let mut skipped_low = 0usize;

    for &(sh_type, _, _, sh_offset, sh_size, sh_link, sh_info, sh_entsize) in &sections {
        if sh_type != SHT_RELA {
            continue;
        }
        let target = match sections.get(sh_info as usize) {
            Some(t) => t,
            None => continue,
        };
        let (_, t_flags, t_addr, _, _, _, _, _) = *target;
        // Debug and other non-allocated sections never reach memory.
        if t_flags & SHF_ALLOC == 0 {
            continue;
        }
        let field_moves = t_addr >= KERNEL_VIRT_BASE;

        let entsize = if sh_entsize == 0 {
            24
        } else {
            sh_entsize as usize
        };
        let count = (sh_size as usize) / entsize;
        for i in 0..count {
            let rela = sh_offset as usize + i * entsize;
            if rela + 24 > bytes.len() {
                bail!("relocation entry runs past the end of the file");
            }
            let r_offset = u64_at(&bytes, rela);
            let r_info = u64_at(&bytes, rela + 8);
            let r_type = (r_info & 0xFFFF_FFFF) as u32;
            let r_sym = (r_info >> 32) as usize;
            let addend = u64_at(&bytes, rela + 16);

            // Where the encoded value points. `sh_link` names the symbol table
            // this relocation section indexes.
            let sym_value = symtab.get(&(sh_link, r_sym)).copied().unwrap_or(0);
            let value_moves =
                sym_value.wrapping_add(addend) >= KERNEL_VIRT_BASE || sym_value >= KERNEL_VIRT_BASE;

            match (r_type, field_moves, value_moves) {
                // Absolute fields in the kernel half encoding a kernel-half
                // value: the ordinary case.
                (R_X86_64_64, true, _) => table.abs64.push(r_offset),
                (R_X86_64_32S, true, _) => table.abs32s.push(r_offset),
                // A plain 32-bit absolute encoding a kernel-half value cannot
                // survive a slide; `code-model=kernel` does not emit these, so
                // refuse rather than silently truncate.
                (R_X86_64_32, _, true) => bail!(
                    "R_X86_64_32 at {r_offset:#x} encodes a kernel-half value; \
                     a slide cannot patch it safely"
                ),
                // The boot stub reaching into the kernel half. PC-relative,
                // but only the TARGET moves, so the displacement must grow.
                (R_X86_64_PC32 | R_X86_64_PLT32, false, true) => {
                    table.pcrel32_into_kernel.push(r_offset)
                }
                // Absolute field in the boot stub encoding a low value, or
                // PC-relative within one half: nothing to do.
                _ => {
                    if !field_moves {
                        skipped_low += 1;
                    }
                }
            }
        }
    }

    if table.total() == 0 {
        bail!("no absolute relocations found — was the kernel linked with --emit-relocs?");
    }
    eprintln!(
        "xtask relocs: {} abs64 + {} abs32s + {} cross-half pcrel = {} sites \
         ({} bytes), {skipped_low} left alone",
        table.abs64.len(),
        table.abs32s.len(),
        table.pcrel32_into_kernel.len(),
        table.total(),
        table.encoded_len(),
    );
    Ok(table)
}

/// Section that holds the table in the linked image.
const RELOC_SECTION: &str = ".kaslr_relocs";

/// Extract the table and write it into the image's reserved section.
///
/// The table is computed from the SAME file it is written back into, which is
/// what keeps it valid: filling a pre-reserved, fixed-size section moves no
/// addresses, so every offset recorded stays correct. Growing the section
/// after extraction would invalidate the whole table, which is why the
/// reservation is a link-time constant and this fails loudly when a table
/// outgrows it.
pub fn patch(elf_path: &Path) -> Result<RelocTable> {
    let table = extract(elf_path)?;
    let encoded = table.encode();

    let bytes = std::fs::read(elf_path)?;
    let (offset, size) = section_by_name(&bytes, RELOC_SECTION)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{} has no {RELOC_SECTION} section — is the kernel linked with the \
             KASLR-aware linker script?",
            elf_path.display()
        )
    })?;
    if encoded.len() > size as usize {
        bail!(
            "relocation table is {} bytes but {RELOC_SECTION} reserves only {size}; \
             raise KASLR_RELOC_RESERVE in the linker script",
            encoded.len()
        );
    }

    let mut out = bytes;
    out[offset as usize..offset as usize + encoded.len()].copy_from_slice(&encoded);
    std::fs::write(elf_path, &out)?;
    Ok(table)
}

/// File offset and size of a named section.
fn section_by_name(bytes: &[u8], want: &str) -> Result<Option<(u64, u64)>> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        bail!("not an ELF image");
    }
    let shoff = u64_at(bytes, 0x28) as usize;
    let shentsize = u16_at(bytes, 0x3A) as usize;
    let shnum = u16_at(bytes, 0x3C) as usize;
    let shstrndx = u16_at(bytes, 0x3E) as usize;

    let strtab_hdr = shoff + shstrndx * shentsize;
    let strtab_off = u64_at(bytes, strtab_hdr + 0x18) as usize;

    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let name_off = u32_at(bytes, sh) as usize;
        let start = strtab_off + name_off;
        let end = bytes[start..].iter().position(|b| *b == 0).unwrap_or(0) + start;
        if &bytes[start..end] == want.as_bytes() {
            return Ok(Some((u64_at(bytes, sh + 0x18), u64_at(bytes, sh + 0x20))));
        }
    }
    Ok(None)
}

/// `SHT_SYMTAB` / `SHT_DYNSYM`.
const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;

/// Map `(symtab section index, symbol index) -> st_value`.
///
/// Keyed by the owning table because a relocation section names its symbol
/// table through `sh_link`; assuming a single global table silently resolves
/// against the wrong one when an image carries both `.symtab` and `.dynsym`.
fn symbol_values(
    bytes: &[u8],
    sections: &[(u32, u64, u64, u64, u64, u32, u32, u64)],
) -> Result<std::collections::HashMap<(u32, usize), u64>> {
    let mut out = std::collections::HashMap::new();
    for (idx, &(sh_type, _, _, sh_offset, sh_size, _, _, sh_entsize)) in sections.iter().enumerate()
    {
        if sh_type != SHT_SYMTAB && sh_type != SHT_DYNSYM {
            continue;
        }
        let entsize = if sh_entsize == 0 {
            24
        } else {
            sh_entsize as usize
        };
        let count = (sh_size as usize) / entsize;
        for i in 0..count {
            let sym = sh_offset as usize + i * entsize;
            if sym + 16 > bytes.len() {
                bail!("symbol entry runs past the end of the file");
            }
            // Elf64_Sym: name u32, info u8, other u8, shndx u16, value u64
            out.insert((idx as u32, i), u64_at(bytes, sym + 8));
        }
    }
    Ok(out)
}
