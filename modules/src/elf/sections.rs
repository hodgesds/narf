//! Special-section recognition for NARF modules.
//!
//! Linux ref: `linux/kernel/module/main.c::find_module_sections`
//! (`main.c:2606`). NARF adds the `.narf_caps` and `.narf_kparams`
//! sections so a module can declare its required caps and runtime
//! parameters without using the dwarf-style modinfo k=v form.

/// Name of the `.modinfo` section (k=v key/value list).
pub const SECT_MODINFO: &str = ".modinfo";

/// Module text (loaded executable).
pub const SECT_TEXT: &str = ".text";

/// Module read-only data (loaded RO).
pub const SECT_RODATA: &str = ".rodata";

/// Module read-write data.
pub const SECT_DATA: &str = ".data";

/// Module uninitialised RW data.
pub const SECT_BSS: &str = ".bss";

/// NARF-only: required caps as `<CapKind>:<Right>` ASCII list, one
/// per newline.
pub const SECT_NARF_CAPS: &str = ".narf_caps";

/// NARF-only: kernel-parameter descriptors. ASCII k=v, one per line.
pub const SECT_NARF_KPARAMS: &str = ".narf_kparams";

/// Section-name classification used by the loader.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SectionKind {
    Modinfo,
    Text,
    Rodata,
    Data,
    Bss,
    NarfCaps,
    NarfKparams,
    Symtab,
    Strtab,
    /// Section we don't load but might walk (rela, note, etc.).
    Other,
}

/// Classify a section by name.
pub fn classify(name: &str) -> SectionKind {
    match name {
        SECT_MODINFO => SectionKind::Modinfo,
        SECT_TEXT => SectionKind::Text,
        SECT_RODATA => SectionKind::Rodata,
        SECT_DATA => SectionKind::Data,
        SECT_BSS => SectionKind::Bss,
        SECT_NARF_CAPS => SectionKind::NarfCaps,
        SECT_NARF_KPARAMS => SectionKind::NarfKparams,
        ".symtab" => SectionKind::Symtab,
        ".strtab" => SectionKind::Strtab,
        _ => SectionKind::Other,
    }
}
