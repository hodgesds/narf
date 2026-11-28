//! Kernel symbol table (`/proc/kallsyms`) generation.
//!
//! Linux builds its table with a multi-pass link (`scripts/link-vmlinux.sh`):
//! link, run `scripts/kallsyms` over `nm -n`, link again with the table, and
//! repeat until the table's own size stops moving the symbols after it. NARF
//! reaches the same end state in one link, the way it already does for the
//! KASLR relocation table (`relocs.rs`): the linker script reserves a
//! fixed-size `.kallsyms` section, and this pass fills it from the symbol
//! table of the very image it is written into. Filling a reservation moves
//! nothing, so every recorded address is the final one — the property
//! Linux's extra passes exist to reach — and the build fails loudly if the
//! table ever outgrows `KALLSYMS_RESERVE` rather than truncating it.
//!
//! The table stores offsets from `_text`, never absolute addresses, so it has
//! no relocation records and the KASLR pass leaves it alone; the kernel adds
//! the runtime `_text` when it prints (`kernel/kallsyms.c::kallsyms_sym_address`).
//!
//! ## What goes in
//!
//! Text and data symbols of the kernel-half image (Linux
//! `CONFIG_KALLSYMS_ALL`), each with the `nm(1)` type letter, filtered as
//! `scripts/mksysmap` and `scripts/kallsyms.c::is_ignored_symbol` filter:
//! no undefined, absolute, debugging, mapping (`$x`/`$d`) or local-label
//! symbols. LLVM's unnamed constants (`anon.<hash>.<n>`) are dropped too; they
//! are rustc's spelling of the `.L__unnamed_*` locals `mksysmap` removes.
//! The low-half boot stub (`.boot`, identity-mapped at its physical address)
//! is not part of the kernel image proper and is excluded.
//!
//! Rust names are demangled to what `nm -C` prints (`rustc-demangle`'s
//! alternate form: no `::h<hash>` suffix). perf does not demangle kernel
//! symbols by default (`symbol_conf.demangle_kernel = false`), so a mangled
//! table would make every `perf report` line an `_ZN...E`. Linux's own Rust
//! symbols are mangled because its C-centric table predates Rust; NARF is
//! all Rust and the readable form is the useful one.

use anyhow::{bail, Context, Result};
use narf_kallsyms::encode::{self, Stats, Symbol};
use std::os::unix::fs::FileExt;
use std::path::Path;

/// Section that holds the table in the linked image.
pub const SECTION: &str = ".kallsyms";

const EM_X86_64: u16 = 0x3E;
const EM_AARCH64: u16 = 0xB7;

const SHT_SYMTAB: u32 = 2;
const SHT_NOBITS: u32 = 8;
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xFF00;
const SHN_ABS: u16 = 0xFFF1;
const SHN_COMMON: u16 = 0xFFF2;

const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STB_GNU_UNIQUE: u8 = 10;

const STT_OBJECT: u8 = 1;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;
const STT_GNU_IFUNC: u8 = 10;

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// The section-header fields this pass reads.
#[derive(Clone, Debug)]
struct Section {
    name: String,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// One `.symtab` entry, name not yet demangled.
#[derive(Clone, Debug)]
struct RawSym {
    name: String,
    info: u8,
    shndx: u16,
    value: u64,
}

struct Elf {
    machine: u16,
    sections: Vec<Section>,
}

fn parse_sections(bytes: &[u8]) -> Result<Elf> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        bail!("not a little-endian ELF64 image");
    }
    let machine = u16_at(bytes, 0x12).context("short header")?;
    let shoff = u64_at(bytes, 0x28).context("short header")? as usize;
    let shentsize = u16_at(bytes, 0x3A).context("short header")? as usize;
    let shnum = u16_at(bytes, 0x3C).context("short header")? as usize;
    let shstrndx = u16_at(bytes, 0x3E).context("short header")? as usize;
    let end = shoff.saturating_add(shnum.saturating_mul(shentsize));
    if shoff == 0 || shentsize < 64 || end > bytes.len() {
        bail!("section header table runs past the end of the file — a truncated image?");
    }
    let mut raw = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        raw.push((
            u32_at(bytes, sh).unwrap(),
            Section {
                name: String::new(),
                sh_type: u32_at(bytes, sh + 0x04).unwrap(),
                flags: u64_at(bytes, sh + 0x08).unwrap(),
                addr: u64_at(bytes, sh + 0x10).unwrap(),
                offset: u64_at(bytes, sh + 0x18).unwrap(),
                size: u64_at(bytes, sh + 0x20).unwrap(),
                link: u32_at(bytes, sh + 0x28).unwrap(),
                entsize: u64_at(bytes, sh + 0x38).unwrap(),
            },
        ));
    }
    let strtab = raw.get(shstrndx).map(|(_, s)| s.clone());
    let mut sections = Vec::with_capacity(shnum);
    for (name_off, mut s) in raw {
        if let Some(st) = &strtab {
            s.name = c_str(bytes, st.offset as usize + name_off as usize).unwrap_or_default();
        }
        sections.push(s);
    }
    Ok(Elf { machine, sections })
}

fn c_str(bytes: &[u8], at: usize) -> Option<String> {
    let tail = bytes.get(at..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn symbols(bytes: &[u8], elf: &Elf) -> Result<Vec<RawSym>> {
    let symtab = elf
        .sections
        .iter()
        .find(|s| s.sh_type == SHT_SYMTAB)
        .context("image has no .symtab — was it stripped?")?;
    let strtab = elf
        .sections
        .get(symtab.link as usize)
        .context(".symtab names no string table")?;
    let entsize = if symtab.entsize == 0 {
        24
    } else {
        symtab.entsize as usize
    };
    let count = symtab.size as usize / entsize;
    let mut out = Vec::with_capacity(count);
    // Entry 0 is the reserved null symbol.
    for i in 1..count {
        let at = symtab.offset as usize + i * entsize;
        let name_off = u32_at(bytes, at).context("symbol runs past the end of the file")?;
        out.push(RawSym {
            name: c_str(bytes, strtab.offset as usize + name_off as usize)
                .context("symbol name runs past the end of the file")?,
            info: bytes[at + 4],
            shndx: u16_at(bytes, at + 6).unwrap(),
            value: u64_at(bytes, at + 8).context("symbol runs past the end of the file")?,
        });
    }
    Ok(out)
}

/// The letter `nm(1)` prints for a symbol (binutils `bfd_decode_symclass`),
/// or `None` for the section/file symbols `nm` does not list.
fn nm_type(sym: &RawSym, sections: &[Section]) -> Option<u8> {
    let bind = sym.info >> 4;
    let kind = sym.info & 0xF;
    if kind == STT_SECTION || kind == STT_FILE {
        return None;
    }
    let weak_object = kind == STT_OBJECT;
    match sym.shndx {
        SHN_UNDEF => {
            return Some(match (bind, weak_object) {
                (STB_WEAK, true) => b'v',
                (STB_WEAK, false) => b'w',
                _ => b'U',
            })
        }
        SHN_ABS => return Some(if bind == STB_LOCAL { b'a' } else { b'A' }),
        SHN_COMMON => return Some(b'C'),
        n if n >= SHN_LORESERVE => return None,
        _ => {}
    }
    if kind == STT_GNU_IFUNC {
        return Some(b'i');
    }
    if bind == STB_WEAK {
        return Some(if weak_object { b'V' } else { b'W' });
    }
    let sec = sections.get(sym.shndx as usize)?;
    let c = if sec.flags & SHF_EXECINSTR != 0 {
        b't'
    } else if sec.flags & SHF_ALLOC == 0 {
        b'n'
    } else if sec.sh_type == SHT_NOBITS {
        b'b'
    } else if sec.flags & SHF_WRITE != 0 {
        b'd'
    } else {
        b'r'
    };
    Some(match bind {
        STB_GLOBAL | STB_GNU_UNIQUE => c.to_ascii_uppercase(),
        _ => c,
    })
}

/// `scripts/mksysmap` and `is_ignored_symbol`: types that never enter the
/// table (undefined, absolute, common, debugging / non-allocated).
fn ignored_type(kind: u8) -> bool {
    matches!(kind, b'U' | b'w' | b'v' | b'a' | b'A' | b'C' | b'N' | b'n')
}

/// `scripts/mksysmap`'s name filters, plus rustc's unnamed constants.
fn ignored_name(name: &str) -> bool {
    name.is_empty()
        // ARM/AArch64 mapping symbols ($x, $d, $x.17).
        || name.starts_with('$')
        // Local labels: .LBB, .Ltmp, .L__unnamed_*.
        || name.starts_with(".L")
        // LLVM private constants: `anon.<crate hash>.<n>[.llvm.<n>]`.
        || name.starts_with("anon.")
        || name.starts_with("__efistub_")
        || name.starts_with("__kcfi_typeid_")
        || name.starts_with("__crc_")
        || name.starts_with("__kstrtab_")
        || name.starts_with("__kstrtabns_")
}

/// What `nm -C` prints for `raw`: Rust legacy (`_ZN…17h<hash>E`) and v0
/// (`_R…`) names demangled without the hash, anything else unchanged.
pub fn display_name(raw: &str) -> String {
    match rustc_demangle::try_demangle(raw) {
        Ok(d) => format!("{d:#}"),
        Err(_) => raw.to_string(),
    }
}

/// The symbol set for one linked image.
#[derive(Debug)]
pub struct Extracted {
    /// Link-time `_text`.
    pub text: u64,
    pub symbols: Vec<Symbol>,
    /// Names cut to `KSYM_NAME_LEN - 1`.
    pub truncated: usize,
}

/// Collect the table's symbols from a linked kernel image.
pub fn extract(bytes: &[u8]) -> Result<Extracted> {
    let elf = parse_sections(bytes)?;
    let base = match elf.machine {
        EM_X86_64 => crate::dev::relocs::KERNEL_VIRT_BASE,
        EM_AARCH64 => crate::dev::relocs::KIMAGE_VOFFSET_AARCH64,
        other => bail!("unsupported e_machine {other:#x} for a kernel symbol table"),
    };
    // The kernel-half image extent; `.boot` sits below it at its physical
    // address and does not move with the slide.
    let mut hi = 0u64;
    for s in &elf.sections {
        if s.flags & SHF_ALLOC != 0 && s.addr >= base {
            hi = hi.max(s.addr + s.size);
        }
    }
    let raw = symbols(bytes, &elf)?;
    let text = raw
        .iter()
        .find(|s| s.name == "_text" && s.shndx != SHN_UNDEF)
        .map(|s| s.value)
        .context(
            "image has no `_text` symbol — perf locates the kernel by it; \
             is it linked with the current build/linker script?",
        )?;
    if text < base {
        bail!("_text at {text:#x} is below the kernel half {base:#x}");
    }

    let mut symbols = Vec::new();
    let mut truncated = 0;
    for s in &raw {
        let Some(kind) = nm_type(s, &elf.sections) else {
            continue;
        };
        if ignored_type(kind) || ignored_name(&s.name) {
            continue;
        }
        if s.value < text || s.value > hi {
            continue;
        }
        let full = display_name(&s.name);
        let name = encode::truncate_name(&full);
        if name.len() != full.len() {
            truncated += 1;
        }
        symbols.push(Symbol {
            addr: s.value,
            kind,
            name: name.to_string(),
        });
    }
    Ok(Extracted {
        text,
        symbols,
        truncated,
    })
}

/// Encode an image's table without writing it.
pub fn generate(bytes: &[u8]) -> Result<(Vec<u8>, Stats, Extracted)> {
    let ex = extract(bytes)?;
    let (blob, stats) = encode::encode(ex.text, ex.symbols.clone())
        .map_err(|e| anyhow::anyhow!("encoding the kernel symbol table: {e}"))?;
    Ok((blob, stats, ex))
}

/// Generate the table and write it into the image's `.kallsyms` reservation,
/// zero-filling the rest so a re-run on the same image is byte-identical.
pub fn patch(elf_path: &Path) -> Result<Stats> {
    let bytes = std::fs::read(elf_path)
        .with_context(|| format!("reading kernel ELF {}", elf_path.display()))?;
    let (blob, stats, ex) = generate(&bytes)?;
    let elf = parse_sections(&bytes)?;
    let sec = elf
        .sections
        .iter()
        .find(|s| s.name == SECTION)
        .with_context(|| {
            format!(
                "{} has no {SECTION} section — is it linked with the current linker script?",
                elf_path.display()
            )
        })?;
    if sec.sh_type == SHT_NOBITS {
        bail!("{SECTION} is NOBITS; it needs file bytes to hold the table");
    }
    if blob.len() as u64 > sec.size {
        bail!(
            "kernel symbol table is {} bytes but {SECTION} reserves only {}; \
             raise KALLSYMS_RESERVE in build/linker/*.ld",
            blob.len(),
            sec.size
        );
    }
    let mut image = blob;
    image.resize(sec.size as usize, 0);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(elf_path)
        .with_context(|| format!("opening {} for writing", elf_path.display()))?;
    file.write_all_at(&image, sec.offset)
        .with_context(|| format!("writing {SECTION} into {}", elf_path.display()))?;
    eprintln!(
        "cargo narf build kallsyms: {} symbols ({} names, {} truncated), {} name bytes -> {} \
         ({} tokens); table {} of {} reserved bytes",
        stats.symbols,
        stats.names,
        ex.truncated,
        stats.raw_name_bytes,
        stats.name_stream_bytes,
        stats.tokens,
        stats.total,
        sec.size
    );
    Ok(stats)
}

/// Render an image's table the way `/proc/kallsyms` does, with addresses
/// moved by `slide` — for symbolising a capture offline.
///
/// Reads the patched `.kallsyms` section when the image has one, so the
/// output is exactly what that kernel serves. An image without one (linked
/// before the section existed, or never patched) gets a table generated from
/// its symbol table instead, which is the same bytes the patch step would
/// have written.
pub fn render(bytes: &[u8], slide: u64) -> Result<String> {
    let elf = parse_sections(bytes)?;
    let patched = elf
        .sections
        .iter()
        .find(|s| s.name == SECTION)
        .and_then(|sec| bytes.get(sec.offset as usize..(sec.offset + sec.size) as usize))
        .filter(|data| narf_kallsyms::Table::parse(data).is_ok());
    let generated;
    let data = match patched {
        Some(data) => data,
        None => {
            eprintln!(
                "cargo narf build kallsyms: image carries no patched {SECTION}; generating from .symtab"
            );
            generated = generate(bytes)?.0;
            &generated[..]
        }
    };
    let table = narf_kallsyms::Table::parse(data)
        .map_err(|e| anyhow::anyhow!("{SECTION} does not hold a table: {e:?}"))?;
    let mut out = String::new();
    let mut name = narf_kallsyms::NameBuf::new();
    for e in table.iter() {
        table
            .name(e.name_index, &mut name)
            .map_err(|err| anyhow::anyhow!("symbol {}: {err:?}", e.index))?;
        out.push_str(&format!(
            "{:016x} {} {}\n",
            table.text_link() + slide + e.offset as u64,
            e.kind as char,
            name.as_str().unwrap_or("?")
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64 for one arch: one section per kind nm distinguishes,
    /// a symbol table, and a zeroed `.kallsyms` reservation.
    struct ElfBuilder {
        machine: u16,
        /// (name, type, flags, addr, size, contents)
        sections: Vec<(String, u32, u64, u64, u64, Vec<u8>)>,
        /// (name, info, section index, value)
        syms: Vec<(String, u8, u16, u64)>,
    }

    const SHT_PROGBITS: u32 = 1;
    const SHT_STRTAB: u32 = 3;

    impl ElfBuilder {
        fn new(machine: u16) -> Self {
            ElfBuilder {
                machine,
                sections: vec![(String::new(), 0, 0, 0, 0, Vec::new())],
                syms: Vec::new(),
            }
        }
        fn section(&mut self, name: &str, ty: u32, flags: u64, addr: u64, size: u64) -> u16 {
            let contents = if ty == SHT_NOBITS {
                Vec::new()
            } else {
                vec![0; size as usize]
            };
            self.sections
                .push((name.into(), ty, flags, addr, size, contents));
            (self.sections.len() - 1) as u16
        }
        fn sym(&mut self, name: &str, bind: u8, ty: u8, shndx: u16, value: u64) {
            self.syms.push((name.into(), bind << 4 | ty, shndx, value));
        }
        fn build(mut self) -> Vec<u8> {
            // .strtab
            let mut strtab = vec![0u8];
            let mut symtab = vec![0u8; 24];
            for (name, info, shndx, value) in &self.syms {
                let off = strtab.len() as u32;
                strtab.extend_from_slice(name.as_bytes());
                strtab.push(0);
                symtab.extend_from_slice(&off.to_le_bytes());
                symtab.push(*info);
                symtab.push(0);
                symtab.extend_from_slice(&shndx.to_le_bytes());
                symtab.extend_from_slice(&value.to_le_bytes());
                symtab.extend_from_slice(&0u64.to_le_bytes());
            }
            let strtab_idx = self.sections.len() as u32 + 1;
            let n = symtab.len() as u64;
            self.sections
                .push((".symtab".into(), SHT_SYMTAB, 0, 0, n, symtab));
            let n = strtab.len() as u64;
            self.sections
                .push((".strtab".into(), SHT_STRTAB, 0, 0, n, strtab));
            let mut shstr = vec![0u8];
            let mut name_offs = Vec::new();
            for s in &self.sections {
                name_offs.push(shstr.len() as u32);
                shstr.extend_from_slice(s.0.as_bytes());
                shstr.push(0);
            }
            name_offs.push(shstr.len() as u32);
            shstr.extend_from_slice(b".shstrtab\0");
            let n = shstr.len() as u64;
            self.sections
                .push((".shstrtab".into(), SHT_STRTAB, 0, 0, n, shstr));

            let mut file = vec![0u8; 64];
            let mut offsets = Vec::new();
            for s in &self.sections {
                offsets.push(file.len() as u64);
                file.extend_from_slice(&s.5);
                while file.len() % 8 != 0 {
                    file.push(0);
                }
            }
            let shoff = file.len() as u64;
            for (i, s) in self.sections.iter().enumerate() {
                let mut sh = [0u8; 64];
                let name = if i == 0 { 0 } else { name_offs[i] };
                sh[0..4].copy_from_slice(&name.to_le_bytes());
                sh[4..8].copy_from_slice(&s.1.to_le_bytes());
                sh[8..16].copy_from_slice(&s.2.to_le_bytes());
                sh[16..24].copy_from_slice(&s.3.to_le_bytes());
                sh[24..32].copy_from_slice(&offsets[i].to_le_bytes());
                sh[32..40].copy_from_slice(&s.4.to_le_bytes());
                if s.0 == ".symtab" {
                    sh[40..44].copy_from_slice(&strtab_idx.to_le_bytes());
                    sh[56..64].copy_from_slice(&24u64.to_le_bytes());
                }
                file.extend_from_slice(&sh);
            }
            file[..4].copy_from_slice(b"\x7fELF");
            file[4] = 2;
            file[5] = 1;
            file[6] = 1;
            file[0x12..0x14].copy_from_slice(&self.machine.to_le_bytes());
            file[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
            file[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
            file[0x3C..0x3E].copy_from_slice(&(self.sections.len() as u16).to_le_bytes());
            file[0x3E..0x40].copy_from_slice(&((self.sections.len() - 1) as u16).to_le_bytes());
            file
        }
    }

    const BASE: u64 = crate::dev::relocs::KERNEL_VIRT_BASE;

    /// An x86_64-shaped image: boot stub low, kernel half above.
    fn kernel_image(reserve: u64) -> Vec<u8> {
        let mut b = ElfBuilder::new(EM_X86_64);
        let boot = b.section(
            ".boot",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            0x1000_0000,
            0x100,
        );
        let text_addr = BASE + 0x1001_7000;
        let text = b.section(
            ".text",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            text_addr,
            0x1000,
        );
        let ksyms = b.section(
            SECTION,
            SHT_PROGBITS,
            SHF_ALLOC,
            text_addr + 0x1000,
            reserve,
        );
        let ro_addr = text_addr + 0x1000 + reserve;
        let rodata = b.section(".rodata", SHT_PROGBITS, SHF_ALLOC, ro_addr, 0x100);
        let data = b.section(
            ".data",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_WRITE,
            ro_addr + 0x1000,
            0x100,
        );
        let bss = b.section(
            ".bss",
            SHT_NOBITS,
            SHF_ALLOC | SHF_WRITE,
            ro_addr + 0x2000,
            0x100,
        );
        b.section(".comment", SHT_PROGBITS, 0, 0, 4);

        b.sym("pdpt", STB_LOCAL, 0, boot, 0x1000_0010);
        b.sym("_text", STB_GLOBAL, 0, text, text_addr);
        b.sym("_stext", STB_GLOBAL, 0, text, text_addr);
        b.sym("_etext", STB_GLOBAL, 0, text, text_addr + 0x1000);
        b.sym("__kallsyms_start", STB_GLOBAL, 0, ksyms, text_addr + 0x1000);
        // _ZN11narf_kernel4main17h0123456789abcdefE
        b.sym(
            "_ZN11narf_kernel4main17h0123456789abcdefE",
            STB_GLOBAL,
            2,
            text,
            text_addr + 0x10,
        );
        b.sym(
            "_ZN4core3ptr13drop_in_place17h00000000000000aaE",
            STB_LOCAL,
            2,
            text,
            text_addr + 0x40,
        );
        b.sym(
            "_ZN4core3ptr13drop_in_place17h00000000000000bbE",
            STB_LOCAL,
            2,
            text,
            text_addr + 0x80,
        );
        b.sym("$x.12", STB_LOCAL, 0, text, text_addr + 0x90);
        b.sym(".Ltmp3", STB_LOCAL, 0, text, text_addr + 0x94);
        b.sym("weak_fn", STB_WEAK, 2, text, text_addr + 0x100);
        b.sym("undefined_ref", STB_GLOBAL, 0, SHN_UNDEF, 0);
        b.sym("__kaslr_relocs_phys", STB_GLOBAL, 0, SHN_ABS, 0x1234);
        b.sym("RODATA_G", STB_GLOBAL, 1, rodata, ro_addr);
        b.sym(
            "anon.0031056705ae321912dd312eaf2092d7.0.llvm.1175565857558",
            STB_LOCAL,
            1,
            rodata,
            ro_addr + 8,
        );
        b.sym("rodata_l", STB_LOCAL, 1, rodata, ro_addr + 0x10);
        b.sym("DATA_G", STB_GLOBAL, 1, data, ro_addr + 0x1000);
        b.sym("data_l", STB_LOCAL, 1, data, ro_addr + 0x1008);
        b.sym("BSS_G", STB_GLOBAL, 1, bss, ro_addr + 0x2000);
        b.sym("bss_l", STB_LOCAL, 1, bss, ro_addr + 0x2008);
        b.sym("_end", STB_GLOBAL, 0, bss, ro_addr + 0x2100);
        b.sym("file.rs", STB_LOCAL, STT_FILE, SHN_ABS, 0);
        b.build()
    }

    fn listing(bytes: &[u8]) -> Vec<(u64, char, String)> {
        render(bytes, 0)
            .unwrap()
            .lines()
            .map(|l| {
                let mut p = l.splitn(3, ' ');
                (
                    u64::from_str_radix(p.next().unwrap(), 16).unwrap(),
                    p.next().unwrap().chars().next().unwrap(),
                    p.next().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn patch_fills_the_reservation_with_a_decodable_table() {
        let dir = std::env::temp_dir().join(format!("narf-kallsyms-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("narf-frame");
        std::fs::write(&path, kernel_image(0x4000)).unwrap();
        let stats = patch(&path).unwrap();
        let first = std::fs::read(&path).unwrap();
        // Idempotent: patching the patched image changes nothing.
        patch(&path).unwrap();
        assert_eq!(first, std::fs::read(&path).unwrap());

        let text = BASE + 0x1001_7000;
        let ro = text + 0x1000 + 0x4000;
        let got = listing(&first);
        assert_eq!(got.len(), stats.symbols);
        let want: Vec<(u64, char, &str)> = vec![
            // Same address, same tie-break class: symbol-table order.
            (text, 'T', "_text"),
            (text, 'T', "_stext"),
            (text + 0x10, 'T', "narf_kernel::main"),
            (text + 0x40, 't', "core::ptr::drop_in_place"),
            (text + 0x80, 't', "core::ptr::drop_in_place"),
            (text + 0x100, 'W', "weak_fn"),
            (text + 0x1000, 'T', "_etext"),
            (text + 0x1000, 'R', "__kallsyms_start"),
            (ro, 'R', "RODATA_G"),
            (ro + 0x10, 'r', "rodata_l"),
            (ro + 0x1000, 'D', "DATA_G"),
            (ro + 0x1008, 'd', "data_l"),
            (ro + 0x2000, 'B', "BSS_G"),
            (ro + 0x2008, 'b', "bss_l"),
            (ro + 0x2100, 'B', "_end"),
        ];
        let got_ref: Vec<(u64, char, &str)> =
            got.iter().map(|(a, k, n)| (*a, *k, n.as_str())).collect();
        assert_eq!(got_ref, want);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn slide_moves_every_rendered_address() {
        let dir = std::env::temp_dir().join(format!("narf-kallsyms-slide-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("narf-frame");
        std::fs::write(&path, kernel_image(0x4000)).unwrap();
        patch(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let plain = render(&bytes, 0).unwrap();
        let slid = render(&bytes, 0x1ee0_0000).unwrap();
        for (a, b) in plain.lines().zip(slid.lines()) {
            let x = u64::from_str_radix(&a[..16], 16).unwrap();
            let y = u64::from_str_radix(&b[..16], 16).unwrap();
            assert_eq!(y - x, 0x1ee0_0000);
            assert_eq!(a[16..], b[16..]);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_outgrown_reservation_fails_the_build() {
        let dir = std::env::temp_dir().join(format!("narf-kallsyms-small-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("narf-frame");
        std::fs::write(&path, kernel_image(64)).unwrap();
        let err = patch(&path).unwrap_err().to_string();
        assert!(err.contains("KALLSYMS_RESERVE"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_image_without_text_is_refused() {
        let mut b = ElfBuilder::new(EM_X86_64);
        let t = b.section(
            ".text",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            BASE + 0x1000,
            16,
        );
        b.sym("f", STB_GLOBAL, 2, t, BASE + 0x1000);
        let err = extract(&b.build()).unwrap_err().to_string();
        assert!(err.contains("_text"), "{err}");
    }

    #[test]
    fn rust_names_demangle_like_nm_c() {
        // Legacy mangling: hash dropped, escapes decoded.
        assert_eq!(
            display_name("_ZN11narf_kernel4main17h0123456789abcdefE"),
            "narf_kernel::main"
        );
        let component = "_$LT$narf_drivers_gpu..Mode$u20$as$u20$core..cmp..PartialEq$GT$";
        assert_eq!(
            display_name(&format!(
                "_ZN{}{component}2eq17h1111111111111111E",
                component.len()
            )),
            "<narf_drivers_gpu::Mode as core::cmp::PartialEq>::eq"
        );
        // v0 mangling.
        assert_eq!(display_name("_RNvCs1234_7mycrate3foo"), "mycrate::foo");
        // Not Rust: unchanged.
        assert_eq!(display_name("memcpy"), "memcpy");
        assert_eq!(display_name("_text"), "_text");
    }

    #[test]
    fn nm_letters_follow_binutils() {
        let secs = vec![
            Section {
                name: String::new(),
                sh_type: 0,
                flags: 0,
                addr: 0,
                offset: 0,
                size: 0,
                link: 0,
                entsize: 0,
            },
            Section {
                name: ".text".into(),
                sh_type: 1,
                flags: SHF_ALLOC | SHF_EXECINSTR,
                addr: 0,
                offset: 0,
                size: 0,
                link: 0,
                entsize: 0,
            },
            Section {
                name: ".debug_info".into(),
                sh_type: 1,
                flags: 0,
                addr: 0,
                offset: 0,
                size: 0,
                link: 0,
                entsize: 0,
            },
        ];
        let s = |info: u8, shndx: u16| RawSym {
            name: "x".into(),
            info,
            shndx,
            value: 0,
        };
        assert_eq!(nm_type(&s(STB_GLOBAL << 4 | 2, 1), &secs), Some(b'T'));
        assert_eq!(nm_type(&s(STB_LOCAL << 4 | 2, 1), &secs), Some(b't'));
        assert_eq!(nm_type(&s(STB_WEAK << 4 | 2, 1), &secs), Some(b'W'));
        assert_eq!(nm_type(&s(STB_WEAK << 4 | 1, 1), &secs), Some(b'V'));
        assert_eq!(nm_type(&s(STB_WEAK << 4 | 2, 0), &secs), Some(b'w'));
        assert_eq!(nm_type(&s(STB_GLOBAL << 4, 0), &secs), Some(b'U'));
        assert_eq!(nm_type(&s(STB_GLOBAL << 4, SHN_ABS), &secs), Some(b'A'));
        assert_eq!(nm_type(&s(STB_LOCAL << 4, 2), &secs), Some(b'n'));
        assert_eq!(nm_type(&s(STB_LOCAL << 4 | STT_SECTION, 1), &secs), None);
        assert_eq!(nm_type(&s(STB_LOCAL << 4 | STT_FILE, SHN_ABS), &secs), None);
        assert!(ignored_type(b'w') && ignored_type(b'A') && ignored_type(b'U'));
        assert!(!ignored_type(b'T') && !ignored_type(b'W') && !ignored_type(b'b'));
    }
}
