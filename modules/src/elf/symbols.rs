//! ELF64 symbol-table decoding.
//!
//! Linux ref: `linux/include/uapi/linux/elf.h` (`Elf64_Sym`) and
//! `linux/kernel/module/main.c::layout_symtab` (`main.c:2391`).
//!
//! A relocatable module's `.symtab` holds:
//!   * UND symbols (st_shndx = 0) — references to kernel exports or
//!     other module symbols, resolved at load time.
//!   * Defined symbols (st_shndx > 0 and < SHN_LORESERVE) — local +
//!     exported definitions; the relocator picks them up via section
//!     placement.

use core::convert::TryInto;

use super::header::{string_in_table, Elf64SectionHeader};

/// Special section index for undefined symbols.
pub const SHN_UNDEF: u16 = 0;
/// Reserved section index lower bound. Anything above this is a
/// special marker (SHN_ABS, SHN_COMMON, etc.) and not a real section.
pub const SHN_LORESERVE: u16 = 0xFF00;
pub const SHN_ABS: u16 = 0xFFF1;
pub const SHN_COMMON: u16 = 0xFFF2;

/// Symbol-binding values: high nibble of `st_info`.
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

/// Symbol-type values: low nibble of `st_info`.
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;

/// One decoded ELF64 symbol-table entry. We don't preserve st_other.
#[derive(Copy, Clone, Debug)]
pub struct Elf64Symbol {
    pub st_name: u32,
    pub st_info: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Elf64Symbol {
    #[inline]
    pub fn bind(&self) -> u8 {
        self.st_info >> 4
    }
    #[inline]
    pub fn ty(&self) -> u8 {
        self.st_info & 0x0F
    }
    /// True if this symbol references something outside the module.
    #[inline]
    pub fn is_undefined(&self) -> bool {
        self.st_shndx == SHN_UNDEF
    }
}

/// Iterate the symbol table.
#[derive(Debug)]
pub struct SymbolTable<'a> {
    bytes: &'a [u8],
    symtab: Elf64SectionHeader,
    strtab: Elf64SectionHeader,
}

impl<'a> SymbolTable<'a> {
    pub fn new(bytes: &'a [u8], symtab: Elf64SectionHeader, strtab: Elf64SectionHeader) -> Self {
        Self {
            bytes,
            symtab,
            strtab,
        }
    }

    pub fn len(&self) -> usize {
        if self.symtab.sh_entsize == 0 {
            return 0;
        }
        (self.symtab.sh_size / self.symtab.sh_entsize) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read the symbol at `idx`. Returns `None` if out of range or the
    /// section is too short.
    pub fn get(&self, idx: usize) -> Option<Elf64Symbol> {
        if idx >= self.len() {
            return None;
        }
        let entsize = self.symtab.sh_entsize as usize;
        let base = self.symtab.sh_offset as usize + idx * entsize;
        if base + 24 > self.bytes.len() {
            return None;
        }
        let b = self.bytes;
        Some(Elf64Symbol {
            st_name: u32::from_le_bytes(b[base..base + 4].try_into().ok()?),
            st_info: b[base + 4],
            // st_other = b[base + 5] — ignored
            st_shndx: u16::from_le_bytes(b[base + 6..base + 8].try_into().ok()?),
            st_value: u64::from_le_bytes(b[base + 8..base + 16].try_into().ok()?),
            st_size: u64::from_le_bytes(b[base + 16..base + 24].try_into().ok()?),
        })
    }

    /// Look up a symbol's display name.
    pub fn name(&self, sym: &Elf64Symbol) -> &'a str {
        string_in_table(self.bytes, &self.strtab, sym.st_name)
    }
}
