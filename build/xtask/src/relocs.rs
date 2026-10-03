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

/// `R_AARCH64_ABS64` — a full 64-bit word. The only aarch64 class a slide has
/// to touch: under `code-model=small` every other absolute reference is an
/// ADRP+ADD pair, and those are PC-relative, so field and target move together.
const R_AARCH64_ABS64: u32 = 257;
/// `R_AARCH64_ABS32` — cannot hold a kernel-half address at all, so one
/// encoding a value that moves is refused rather than truncated.
const R_AARCH64_ABS32: u32 = 258;
/// Branch relocations. Slide-invariant within one half; across halves they mean
/// LLD inserted a thunk, which this table cannot see — refused, see below.
const R_AARCH64_JUMP26: u32 = 282;
const R_AARCH64_CALL26: u32 = 283;

/// `e_machine` values, for picking the kernel-half base out of a linked image
/// instead of being told which arch it is.
const EM_X86_64: u16 = 0x3E;
const EM_AARCH64: u16 = 0xB7;

/// Kernel-half base. Sections at or above this slide; the boot stub below it,
/// linked at `KERNEL_LOAD_BASE` so it can run before the MMU, does not.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
/// aarch64's kernel IMAGE offset — `KIMAGE_VOFFSET` in
/// `build/linker/aarch64.ld`, NOT its `KERNEL_VIRT_BASE`.
///
/// What this constant has to be is the base the image is linked against, since
/// it decides both which fields move and what the encoded offsets are relative
/// to. On aarch64 those differ: `KERNEL_VIRT_BASE` is the linear map of RAM and
/// the image sits below it at its own offset, so using the linear base here
/// classified every single image site as belonging to the boot stub —
/// `0 abs64 ... 606237 low left alone` — and the slide was applied to the page
/// tables while no absolute address was patched.
pub const KIMAGE_VOFFSET_AARCH64: u64 = 0xFFFF_FF7F_8000_0000;

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
    /// 64-bit absolute fields in the LOW half encoding a kernel-half value.
    ///
    /// aarch64's boot stub reaches the kernel half through literal pools
    /// (`ldr x16, =_start_rust`), so the field sits at a physical address while
    /// the value it holds slides. Stored as physical addresses, like
    /// [`Self::pcrel32_into_kernel`].
    ///
    /// x86_64 has none: its boot stub is 32-bit code using `R_X86_64_32` and
    /// PC32. `extract` refuses a nonzero count there rather than emit a list
    /// the apply pass would ignore.
    pub abs64_low: Vec<u64>,
    /// Kernel-half base this table's offsets are relative to — which arch's,
    /// decided by the image's `e_machine`.
    pub base: u64,
}

impl RelocTable {
    pub fn total(&self) -> usize {
        self.abs64.len() + self.abs32s.len() + self.pcrel32_into_kernel.len() + self.abs64_low.len()
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
        // Was reserved. x86_64's apply pass reads the three counts above and
        // never this word, so giving it a meaning is backwards compatible.
        out.extend_from_slice(&(self.abs64_low.len() as u32).to_le_bytes());
        for list in [&self.abs64, &self.abs32s] {
            for va in list {
                out.extend_from_slice(&((va - self.base) as u32).to_le_bytes());
            }
        }
        // Already physical: the boot stub runs at its load address.
        for pa in &self.pcrel32_into_kernel {
            out.extend_from_slice(&(*pa as u32).to_le_bytes());
        }
        for pa in &self.abs64_low {
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

    // The image says which arch it is; nothing has to pass it in, and a
    // mismatch between the caller's idea and the file's is impossible.
    let e_machine = u16_at(&bytes, 0x12);
    let base = match e_machine {
        EM_X86_64 => KERNEL_VIRT_BASE,
        EM_AARCH64 => KIMAGE_VOFFSET_AARCH64,
        other => bail!("unsupported e_machine {other:#x} for a KASLR relocation table"),
    };

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

    let image = image_extent(&sections, base);

    let mut table = RelocTable::default();
    let mut skipped_low = 0usize;
    // Kernel-half absolute fields deliberately left unpatched because the
    // value they encode does not move (a physical address or a constant).
    // Counted separately: a site that is neither patched nor reported is
    // indistinguishable from one the parser never saw.
    let mut skipped_static = 0usize;

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
        // Unlike the encoded value (see `value_moves`), the field needs no
        // image bound: it always lies inside its target section, and
        // `image_extent` is the span of exactly the allocated sections at or
        // above `base`. A field at or above `base` is therefore in the image.
        let field_moves = t_addr >= base;

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
            let value_moves = value_moves(&image, sym_value, addend);

            if e_machine == EM_AARCH64 {
                match (r_type, field_moves, value_moves) {
                    // The only class a slide has to touch. Under
                    // `code-model=small` every other absolute reference is an
                    // ADRP+ADD pair: PC-relative, so field and target move
                    // together and the encoding is unchanged.
                    (R_AARCH64_ABS64, true, true) => table.abs64.push(r_offset),
                    // The boot stub's literal pools — `ldr x16, =_start_rust`.
                    // The field is at a physical address in `.boot`; the value
                    // it holds is in the kernel half and slides.
                    (R_AARCH64_ABS64, false, true) => table.abs64_low.push(r_offset),
                    // 32 bits cannot hold a kernel-half address. Refuse rather
                    // than truncate.
                    (R_AARCH64_ABS32, _, true) => bail!(
                        "R_AARCH64_ABS32 at {r_offset:#x} encodes a kernel-half value; \
                         a slide cannot patch it safely"
                    ),
                    // A branch out of the low half into the kernel half is
                    // ~512 GiB, far outside CALL26/JUMP26 range, so LLD
                    // silently inserts a range-extension thunk:
                    //
                    //     ldr x16, [pc+8] ; br x16 ; .quad <far target>
                    //
                    // That `.quad` holds a kernel-half address and carries NO
                    // relocation record — LLD resolves it at link time, so
                    // `--emit-relocs` reports nothing and this table cannot
                    // see it. Under a slide the branch would still reach the
                    // thunk and the thunk would jump to the unslid address.
                    //
                    // `boot.S` avoids it by calling indirectly through a
                    // literal (`ldr x16, =sym ; blr x16`), which produces an
                    // ABS64 record the table does carry. Refusing here is what
                    // stops that being undone: the failure mode is a kernel
                    // that boots fine with the slide disabled and jumps into
                    // nothing with it enabled.
                    (R_AARCH64_CALL26 | R_AARCH64_JUMP26, false, true) => bail!(
                        "{} at {r_offset:#x} branches from the boot stub into the kernel half; \
                         LLD will insert a thunk whose literal no relocation record covers. \
                         Call indirectly through a literal instead (see boot.S).",
                        if r_type == R_AARCH64_CALL26 {
                            "R_AARCH64_CALL26"
                        } else {
                            "R_AARCH64_JUMP26"
                        }
                    ),
                    (R_AARCH64_ABS64, true, false) => skipped_static += 1,
                    _ => {
                        if !field_moves {
                            skipped_low += 1;
                        }
                    }
                }
            } else {
                match (r_type, field_moves, value_moves) {
                    // Absolute fields in the kernel half encoding a kernel-half
                    // value: the ordinary case.
                    //
                    // `value_moves` is load-bearing, not decoration. A kernel-half
                    // field can encode a value that does NOT move, and sliding it
                    // corrupts it. The linker script defines `__kernel_start` and
                    // `__kernel_end` as PHYSICAL addresses (before/minus
                    // `KERNEL_VIRT_BASE`), yet emits them with a real section
                    // index rather than SHN_ABS — so they look like any other
                    // symbol here. Adding the slide to them made the frame
                    // allocator reserve `[start + slide, end + slide)`, leaving the
                    // image's first `slide` bytes free for the buddy to hand out,
                    // and made `kernel_exec_phys_range` mark the corresponding
                    // kernel text NX. Matching on the value, not just the field,
                    // is what distinguishes a pointer from a physical constant.
                    (R_X86_64_64, true, true) => table.abs64.push(r_offset),
                    (R_X86_64_32S, true, true) => table.abs32s.push(r_offset),
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
                    (R_X86_64_64 | R_X86_64_32S, true, false) => skipped_static += 1,
                    _ => {
                        if !field_moves {
                            skipped_low += 1;
                        }
                    }
                }
            }
        }
    }

    table.base = base;

    // x86_64's apply pass in `boot.S` reads three counts and stops; a fourth
    // list would be silently ignored rather than applied. Nothing should
    // produce one there — the 32-bit boot stub uses R_X86_64_32 and PC32 — so
    // refuse instead of emitting something that looks handled.
    if e_machine == EM_X86_64 && !table.abs64_low.is_empty() {
        bail!(
            "{} low-half R_X86_64_64 sites encode kernel-half values; the x86_64 \
             apply pass has no list for them",
            table.abs64_low.len()
        );
    }

    if table.total() == 0 {
        bail!("no absolute relocations found — was the kernel linked with --emit-relocs?");
    }
    eprintln!(
        "xtask relocs: {} abs64 + {} abs32s + {} cross-half pcrel + {} low abs64 \
         = {} sites ({} bytes), {skipped_low} low + {skipped_static} non-moving left alone",
        table.abs64.len(),
        table.abs32s.len(),
        table.pcrel32_into_kernel.len(),
        table.abs64_low.len(),
        table.total(),
        table.encoded_len(),
    );
    Ok(table)
}

/// The VA extent of the kernel-half image: every allocated section at or
/// above `base`, end inclusive so a one-past-the-end symbol still counts.
/// A slide moves exactly this range and nothing else.
///
/// "At or above `base`" is not the same thing on aarch64. There the linear
/// map (`KERNEL_VIRT_BASE`, 0xFFFF_FF80_0000_0000) sits ABOVE the image
/// offset, so a value in it also compares `>= base` — yet the linear map
/// does not move with the image. `boot.S`'s `ldr x0, =stack_top_virt`
/// (`stack_top + KERNEL_VIRT_BASE`) was slid on that basis, which put the
/// BSP's boot stack on the linear alias of `stack_top + slide`: the
/// kernel's own text/data for small slides, and buddy-owned RAM for larger
/// ones, so the stack and whatever the buddy placed there overwrote each
/// other at random. Bound the test by the image itself.
fn image_extent(
    sections: &[(u32, u64, u64, u64, u64, u32, u32, u64)],
    base: u64,
) -> std::ops::RangeInclusive<u64> {
    let (lo, hi) = sections
        .iter()
        .filter(|s| s.1 & SHF_ALLOC != 0 && s.2 >= base && s.4 != 0)
        .fold((u64::MAX, 0u64), |(lo, hi), s| {
            (lo.min(s.2), hi.max(s.2.saturating_add(s.4)))
        });
    lo..=hi
}

/// Whether a relocation encoding `sym_value + addend` points at something the
/// slide moves. Either form counts: a symbol in the image with an addend that
/// steps outside it is still an image address. That happens below the image
/// as well as past its end: a PC-relative record's `-4` addend puts a call to
/// the image's first byte four bytes under it.
fn value_moves(image: &std::ops::RangeInclusive<u64>, sym_value: u64, addend: u64) -> bool {
    image.contains(&sym_value.wrapping_add(addend)) || image.contains(&sym_value)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A linked aarch64 kernel's allocated sections (`readelf -S`), reduced to
    /// what `image_extent` reads: `sh_flags`, `sh_addr`, `sh_size`. `.boot`
    /// sits at its load address; the image at `KIMAGE_VOFFSET + phys`.
    fn aarch64_sections() -> Vec<(u32, u64, u64, u64, u64, u32, u32, u64)> {
        let alloc = |addr: u64, size: u64| (1, SHF_ALLOC, addr, 0, size, 0, 0, 0);
        vec![
            alloc(0x4008_0000, 0x1_9200),             // .boot
            alloc(0xFFFF_FF7F_C009_A000, 0xE5_A418),  // .text
            alloc(0xFFFF_FF7F_C18C_1000, 0x315_3C50), // .bss
            alloc(0xFFFF_FF7F_C4A1_4C60, 0x10),       // .ap_boot_syms, last
            (2, 0, 0, 0, 0x1000, 0, 0, 0),            // .symtab: not loaded
        ]
    }

    #[test]
    fn aarch64_linear_map_above_the_image_does_not_move() {
        let image = image_extent(&aarch64_sections(), KIMAGE_VOFFSET_AARCH64);
        let end = 0xFFFF_FF7F_C4A1_4C70;
        // `stack_top_virt`: the linear alias of the boot stack, above `base`
        // but outside the image. Sliding it is what moved the BSP's SP off
        // its own stack.
        assert!(!value_moves(&image, 0xFFFF_FF80_4009_9000, 0));
        // A physical constant such as `__kernel_start` stays put too.
        assert!(!value_moves(&image, 0x4008_0000, 0));
        // In the image, and one past its end (`__kernel_end`-style symbols).
        assert!(value_moves(&image, 0xFFFF_FF7F_C009_A000, 0x40));
        assert!(value_moves(&image, end, 0));
    }

    const SHT_NOBITS: u32 = 8;

    /// One section of a synthetic image: `(sh_type, sh_flags, sh_addr,
    /// sh_size, sh_link, sh_info, sh_entsize, contents)`. Allocated sections
    /// are `SHT_NOBITS`, since `extract` reads only their address and size.
    type Sec = (u32, u64, u64, u64, u32, u32, u64, Vec<u8>);

    fn nobits(addr: u64, size: u64) -> Sec {
        (SHT_NOBITS, SHF_ALLOC, addr, size, 0, 0, 0, Vec::new())
    }

    /// `Elf64_Sym` entries with the given values, after the null symbol.
    fn symtab(values: &[u64]) -> Sec {
        let mut d = vec![0u8; 24];
        for v in values {
            let mut e = [0u8; 24];
            e[8..16].copy_from_slice(&v.to_le_bytes());
            d.extend_from_slice(&e);
        }
        let size = d.len() as u64;
        (SHT_SYMTAB, 0, 0, size, 0, 0, 24, d)
    }

    /// `Elf64_Rela` entries `(r_offset, r_type, symbol index, addend)`
    /// against the symbol table in section `link`, patching section `info`.
    fn rela(link: u32, info: u32, entries: &[(u64, u32, u64, i64)]) -> Sec {
        let mut d = Vec::new();
        for &(off, ty, sym, addend) in entries {
            d.extend_from_slice(&off.to_le_bytes());
            d.extend_from_slice(&((sym << 32) | u64::from(ty)).to_le_bytes());
            d.extend_from_slice(&addend.to_le_bytes());
        }
        let size = d.len() as u64;
        (SHT_RELA, 0, 0, size, link, info, 24, d)
    }

    /// Write a section-headers-only ELF64 image and run the real `extract`
    /// on it. Section 0 (the null section) is supplied here.
    fn extract_synthetic(name: &str, e_machine: u16, secs: &[Sec]) -> Result<RelocTable> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in secs {
            offsets.push(64 + data.len() as u64);
            data.extend_from_slice(&s.7);
        }
        let shoff = 64 + data.len() as u64;
        let mut img = vec![0u8; 64];
        img[..4].copy_from_slice(b"\x7fELF");
        img[4] = 2; // ELFCLASS64
        img[5] = 1; // little-endian
        img[6] = 1; // EV_CURRENT
        img[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        img[0x12..0x14].copy_from_slice(&e_machine.to_le_bytes());
        img[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        img[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        img[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        img[0x3C..0x3E].copy_from_slice(&(secs.len() as u16 + 1).to_le_bytes());
        img.extend_from_slice(&data);
        img.extend_from_slice(&[0u8; 64]); // null section header
        for (s, off) in secs.iter().zip(offsets) {
            let mut h = [0u8; 64];
            h[0x04..0x08].copy_from_slice(&s.0.to_le_bytes());
            h[0x08..0x10].copy_from_slice(&s.1.to_le_bytes());
            h[0x10..0x18].copy_from_slice(&s.2.to_le_bytes());
            h[0x18..0x20].copy_from_slice(&off.to_le_bytes());
            h[0x20..0x28].copy_from_slice(&s.3.to_le_bytes());
            h[0x28..0x2C].copy_from_slice(&s.4.to_le_bytes());
            h[0x2C..0x30].copy_from_slice(&s.5.to_le_bytes());
            h[0x38..0x40].copy_from_slice(&s.6.to_le_bytes());
            img.extend_from_slice(&h);
        }
        let path =
            std::env::temp_dir().join(format!("xtask-relocs-{name}-{}.elf", std::process::id()));
        std::fs::write(&path, &img).unwrap();
        let table = extract(&path);
        std::fs::remove_file(&path).unwrap();
        table
    }

    /// The aarch64 linear-map literal through the real entry point.
    ///
    /// `boot.S` loads `ldr x0, =stack_top_virt`: an `R_AARCH64_ABS64` in
    /// `.boot` whose symbol lies in the linear map, above `base` but outside
    /// the image. It must not reach `abs64_low`, or the slide moves the BSP's
    /// stack pointer onto the linear alias of `stack_top + slide`. The same
    /// value in a kernel-half field must not reach `abs64` either. The unit
    /// test above calls `value_moves` directly, so it cannot see a call site
    /// in `extract` that stops using it.
    #[test]
    fn extract_leaves_aarch64_linear_map_literals_unslid() {
        const BOOT: u64 = 0x4008_0000;
        const TEXT: u64 = 0xFFFF_FF7F_C009_A000;
        let table = extract_synthetic(
            "aarch64-linear",
            EM_AARCH64,
            &[
                nobits(BOOT, 0x100),  // 1: .boot
                nobits(TEXT, 0x1000), // 2: .text
                symtab(&[
                    TEXT + 0x100,          // 1: an image symbol (`_start_rust`)
                    0xFFFF_FF80_4009_9000, // 2: `stack_top_virt`, linear map
                ]),
                rela(
                    3,
                    1,
                    &[
                        (BOOT + 0x10, R_AARCH64_ABS64, 1, 0),
                        (BOOT + 0x18, R_AARCH64_ABS64, 2, 0),
                    ],
                ),
                rela(
                    3,
                    2,
                    &[
                        (TEXT + 0x8, R_AARCH64_ABS64, 1, 0),
                        (TEXT + 0x10, R_AARCH64_ABS64, 2, 0),
                    ],
                ),
            ],
        )
        .unwrap();
        assert_eq!(table.base, KIMAGE_VOFFSET_AARCH64);
        assert_eq!(table.abs64_low, vec![BOOT + 0x10]);
        assert_eq!(table.abs64, vec![TEXT + 0x8]);
        assert!(table.abs32s.is_empty() && table.pcrel32_into_kernel.is_empty());
    }

    /// The `|| image.contains(&sym_value)` arm of `value_moves`.
    ///
    /// A PC-relative call encodes `S + A - P` with `A = -4`, so when the
    /// target is the first byte of the image, `S + A` lies four bytes BELOW
    /// it. The linked x86_64 kernel has such records: two `R_X86_64_PLT32`
    /// sites whose symbol is at the image's first address with addend -4
    /// (both within the kernel half, where the outcome is the same either
    /// way). From the boot stub the same shape is `call _start_rust` with
    /// `_start_rust` linked first; judged by `S + A` alone it would be
    /// counted as low-to-low and its displacement left unpatched.
    #[test]
    fn extract_slides_boot_stub_call_to_first_image_byte() {
        const BOOT: u64 = 0x100_0000;
        const TEXT: u64 = 0xFFFF_FFFF_8101_6000;
        let table = extract_synthetic(
            "x86-first-byte",
            EM_X86_64,
            &[
                nobits(BOOT, 0x100),  // 1: boot stub
                nobits(TEXT, 0x1000), // 2: .text
                symtab(&[TEXT]),      // 1: the image's first byte
                rela(3, 1, &[(BOOT + 0x10, R_X86_64_PLT32, 1, -4)]),
                rela(3, 2, &[(TEXT + 0x8, R_X86_64_64, 1, 0)]),
            ],
        )
        .unwrap();
        assert_eq!(table.base, KERNEL_VIRT_BASE);
        assert_eq!(table.pcrel32_into_kernel, vec![BOOT + 0x10]);
        assert_eq!(table.abs64, vec![TEXT + 0x8]);
        assert!(table.abs32s.is_empty() && table.abs64_low.is_empty());
    }
}
