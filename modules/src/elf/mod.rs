//! ELF64 parsing for NARF kernel modules.
//!
//! Submodules:
//!   * `header`   — Elf64 file/program/section header parsing.
//!   * `symbols`  — `.symtab` walker + `.strtab` resolver.
//!   * `reloc`    — `.rela.*` decoder + per-arch apply.
//!   * `sections` — special-section recognition (`.modinfo`,
//!                  `.narf_caps`, `.narf_kparams`).
//!
//! Linux equivalents:
//!   * `linux/kernel/module/main.c::elf_validity_cache_copy`
//!     (`main.c:1788`) — magic/class/endian/type validation.
//!   * `linux/kernel/module/main.c::find_module_sections`
//!     (`main.c:2606`) — modinfo / symtab / strtab section
//!     identification.
//!   * `linux/arch/x86/kernel/module.c::apply_relocate_add`
//!     (`module.c:219`) — x86_64 relocations.
//!   * `linux/arch/arm64/kernel/module.c::apply_relocate_add`
//!     (`module.c:231`) — aarch64 relocations.

pub mod header;
pub mod reloc;
pub mod sections;
pub mod symbols;

pub use header::{
    parse_header, parse_section, section_name, string_in_table, Elf64Header, Elf64ProgramHeader,
    Elf64SectionHeader, HeaderError, EM_AARCH64, EM_X86_64, ET_REL, SHF_ALLOC, SHF_EXECINSTR,
    SHF_WRITE, SHT_NOBITS, SHT_PROGBITS, SHT_RELA, SHT_STRTAB, SHT_SYMTAB,
};
pub use reloc::{apply_aarch64, apply_x86_64, parse_rela, Elf64Rela, RelocError};
pub use sections::{classify, SectionKind, SECT_MODINFO, SECT_NARF_CAPS};
pub use symbols::{Elf64Symbol, SymbolTable, SHN_UNDEF};

/// Walk every section of an ELF and return `(idx, header, name)` for
/// each. Allocates a small `Vec` so the caller can iterate without
/// re-parsing names every time.
pub fn enumerate_sections<'a>(
    bytes: &'a [u8],
    hdr: &Elf64Header,
) -> alloc::vec::Vec<(usize, Elf64SectionHeader, &'a str)> {
    let mut out = alloc::vec::Vec::with_capacity(hdr.e_shnum as usize);
    for i in 0..hdr.e_shnum as usize {
        if let Ok(s) = parse_section(bytes, hdr, i) {
            let n = section_name(bytes, hdr, &s);
            out.push((i, s, n));
        }
    }
    out
}
