//! ELF64 and (x86_64) i386 ELF32 parser.
//!
//! Spec: `userspace/specification/spec.md`. Turns a byte slice
//! holding an ELF executable into an `ExecImage` populated with
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
//! - On x86_64, an ELFCLASS32 image naming EM_386/EM_486 parses into an
//!   `Elf32Exec`/`Elf32Dyn` image for the IA-32 compat ABI, as Linux's
//!   `fs/compat_binfmt_elf.c` (`binfmt_elf.c` built for Elf32, gated by
//!   `compat_elf_check_arch`) accepts it. Every other ELFCLASS32 image —
//!   x32 among them — is `Not64Bit`.
//! - Rejects non-ELF magic and byte slices too short for the declared
//!   header offsets.
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

use crate::{DynEntry, ElfProperties, ExecImage, ExecKind, Segment, SegmentFlags, TlsTemplate};

// ── Wire constants (ELF spec) ───────────────────────────────────────

const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

/// `elf_check_arch_ia32` (`arch/x86/include/asm/elf.h`): the two machines an
/// IA-32 ELF32 image may name.
#[cfg(target_arch = "x86_64")]
const EM_386: u16 = 3;
#[cfg(target_arch = "x86_64")]
const EM_486: u16 = 6;

// `e_machine` values. The loader accepts only the machine it is running
// on: an ELF built for another architecture is not executable here, and
// letting one through means the process faults on garbage instructions
// at its entry point instead of `execve` returning ENOEXEC.
// Both are listed so `EM_NATIVE` below reads as a choice between them
// rather than a bare number; only one is live per build.
#[allow(dead_code)]
const EM_X86_64: u16 = 62;
#[allow(dead_code)]
const EM_AARCH64: u16 = 183;

/// `e_machine` value this build can execute. Mirrors Linux's
/// per-arch `elf_check_arch()`.
#[cfg(target_arch = "x86_64")]
const EM_NATIVE: u16 = EM_X86_64;
#[cfg(target_arch = "aarch64")]
const EM_NATIVE: u16 = EM_AARCH64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const EM_NATIVE: u16 = 0;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const PT_PHDR: u32 = 6;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_PROPERTY: u32 = 0x6474e553;

/// `NT_GNU_PROPERTY_TYPE_0` — the only note type `PT_GNU_PROPERTY` carries.
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
/// Property records and the note descriptor are 8-byte aligned in ELF64
/// (`ELF_GNU_PROPERTY_ALIGN`).
const GNU_PROPERTY_ALIGN: usize = 8;
/// A `PT_GNU_PROPERTY` segment is a handful of records; anything beyond this is
/// a malformed or hostile image, and the cap keeps the read bounded without an
/// allocation that tracks the file.
const MAX_PROPERTY_BYTES: u64 = 1024;

const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 1 << 0;
const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 1 << 1;
const GNU_PROPERTY_AARCH64_FEATURE_1_MTE: u32 = 1 << 2;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1 << 0;
const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 1 << 1;

const PF_X: u32 = 1 << 0;
const PF_W: u32 = 1 << 1;
const PF_R: u32 = 1 << 2;

// ── Errors ──────────────────────────────────────────────────────────

/// Errors raised during `parse`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    /// Neither an ELFCLASS64 image nor an ELFCLASS32 image this kernel runs
    /// under its compat ABI (x86_64 runs i386 EM_386/EM_486; x32 and every
    /// other 32-bit machine are refused, as by `compat_elf_check_arch`).
    Not64Bit,
    NotLittleEndian,
    BadType,
    /// `e_machine` names an architecture this kernel cannot execute.
    /// Linux's equivalent is `elf_check_arch()` failing, which
    /// `binfmt_elf` reports as ENOEXEC.
    WrongMachine,
    BadPhoff,
    InterpOutOfBounds,
    /// PT_DYNAMIC's file region (p_offset .. p_offset+p_filesz) lies
    /// outside the input bytes or has a length that isn't a multiple
    /// of `sizeof(Elf64_Dyn) == 16`.
    DynamicOutOfBounds,
    /// PT_TLS file region lies outside the input bytes, mem_size <
    /// file_size, or the alignment isn't a power of two.
    TlsOutOfBounds,
    /// The image source could not produce the bytes that were asked for —
    /// a filesystem error, or a short read before the range the caller needs.
    /// Only a file-backed [`ExecBytes`] can raise it; an in-memory slice fails
    /// its bounds check as `TooShort` instead.
    ImageReadFailed,
    /// The `PT_GNU_PROPERTY` segment is not a well-formed
    /// `NT_GNU_PROPERTY_TYPE_0` note: a record claiming data past the end of
    /// the note, records out of order or duplicated, a misaligned record, a
    /// feature word too short to hold its bitmap, or a segment too small or
    /// implausibly large to be a property note. Linux's `parse_elf_property`
    /// rejects the same shapes with `-ENOEXEC`; guessing would mean silently
    /// reading "no features" and disabling an enforcement the binary asked for.
    BadGnuProperty,
    /// A PT_LOAD claims more file bytes than memory bytes
    /// (`p_filesz > p_memsz`), which cannot be mapped coherently.
    /// Linux's `binfmt_elf` rejects this with EINVAL.
    SegmentFileSizeExceedsMemSize,
    /// More than one PT_TLS segment was present. The SysV ABI allows
    /// only one TLS template per ELF — the dynamic loader's IE-model
    /// thread-pointer arithmetic assumes a single contiguous block.
    MultiplePtTls,
}

// ── Parser ──────────────────────────────────────────────────────────
/// Byte source an ELF image is parsed from.
///
/// `parse` used to require the whole file resident in kernel memory, which is
/// why `execve` read every byte of the binary into a `Vec` before loading it.
/// Demand-paged exec reads only METADATA eagerly — the header, the program
/// header table, PT_INTERP's name and PT_DYNAMIC's array — and leaves PT_LOAD
/// contents to page faults, so the parser reads through this instead of
/// indexing a slice.
///
/// Bounded range reads are what make that possible rather than a "read a
/// metadata prefix" shortcut: PT_DYNAMIC generally lives near the END of the
/// file (redis-server: offset 0x283c90 of 0x2e8bc8), so a prefix covering it
/// would be the entire binary.
pub trait ExecBytes {
    /// Total image size in bytes. Bounds checks are made against this, so it
    /// must describe the whole image even when nothing is resident.
    fn size(&self) -> u64;

    /// Fill `dst` from `off`. A short read is an error: every caller here
    /// needs exactly the range it asked for, and treating a truncated read as
    /// success would silently parse zero bytes as ELF fields.
    fn read_exact_at(&self, off: u64, dst: &mut [u8]) -> Result<(), ElfError>;
}

impl ExecBytes for [u8] {
    #[inline]
    fn size(&self) -> u64 {
        self.len() as u64
    }

    #[inline]
    fn read_exact_at(&self, off: u64, dst: &mut [u8]) -> Result<(), ElfError> {
        let start = usize::try_from(off).map_err(|_| ElfError::TooShort)?;
        let end = start.checked_add(dst.len()).ok_or(ElfError::TooShort)?;
        let src = self.get(start..end).ok_or(ElfError::TooShort)?;
        dst.copy_from_slice(src);
        Ok(())
    }
}

impl ExecBytes for &[u8] {
    #[inline]
    fn size(&self) -> u64 {
        self.len() as u64
    }

    #[inline]
    fn read_exact_at(&self, off: u64, dst: &mut [u8]) -> Result<(), ElfError> {
        let start = usize::try_from(off).map_err(|_| ElfError::TooShort)?;
        let end = start.checked_add(dst.len()).ok_or(ElfError::TooShort)?;
        let src = self.get(start..end).ok_or(ElfError::TooShort)?;
        dst.copy_from_slice(src);
        Ok(())
    }
}

/// ELF file class (`e_ident[EI_CLASS]`) a parse is decoding.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Class {
    Elf32,
    Elf64,
}

/// One program header, widened to the ELF64 field types whatever its class.
#[derive(Copy, Clone, Debug)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

impl Class {
    /// `sizeof(ElfN_Phdr)`.
    const fn phentsize(self) -> usize {
        match self {
            Class::Elf32 => 32,
            Class::Elf64 => 56,
        }
    }

    /// `sizeof(ElfN_Dyn)`.
    const fn dynsize(self) -> usize {
        match self {
            Class::Elf32 => 8,
            Class::Elf64 => 16,
        }
    }

    /// Decode the program header at `off` in `tab`. `Elf32_Phdr` is not
    /// `Elf64_Phdr` with narrower fields: its `p_flags` follows `p_memsz`
    /// (offset 24) instead of `p_type` (offset 4).
    fn phdr(self, tab: &[u8], off: usize) -> Phdr {
        match self {
            Class::Elf64 => Phdr {
                p_type: read_u32(tab, off),
                p_flags: read_u32(tab, off + 0x04),
                p_offset: read_u64(tab, off + 0x08),
                p_vaddr: read_u64(tab, off + 0x10),
                p_filesz: read_u64(tab, off + 0x20),
                p_memsz: read_u64(tab, off + 0x28),
                p_align: read_u64(tab, off + 0x30),
            },
            Class::Elf32 => Phdr {
                p_type: read_u32(tab, off),
                p_offset: u64::from(read_u32(tab, off + 0x04)),
                p_vaddr: u64::from(read_u32(tab, off + 0x08)),
                p_filesz: u64::from(read_u32(tab, off + 0x10)),
                p_memsz: u64::from(read_u32(tab, off + 0x14)),
                p_flags: read_u32(tab, off + 0x18),
                p_align: u64::from(read_u32(tab, off + 0x1C)),
            },
        }
    }

    /// One `ElfN_Dyn { d_tag, d_val }` at `off`. The 32-bit tag is an
    /// `Elf32_Sword`, so it is sign-extended into [`DynEntry::tag`].
    fn dyn_entry(self, buf: &[u8], off: usize) -> (i64, u64) {
        match self {
            Class::Elf64 => (read_i64(buf, off), read_u64(buf, off + 8)),
            Class::Elf32 => (
                i64::from(read_u32(buf, off) as i32),
                u64::from(read_u32(buf, off + 4)),
            ),
        }
    }
}

/// `elf_check_arch_ia32`: may an ELFCLASS32 image naming `machine` run here?
/// Only on x86_64, whose IA-32 compat ABI runs i386 programs.
#[inline]
fn compat32_machine(machine: u16) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        machine == EM_386 || machine == EM_486
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = machine;
        false
    }
}

/// Parse an ELF64 (or, on x86_64, an i386 ELF32) little-endian executable
/// into an `ExecImage`.
/// `argv` / `envp` / `aux` on the returned image are left empty —
/// the caller fills those in before handing the image to the
/// loader.
pub fn parse(bytes: &[u8]) -> Result<ExecImage, ElfError> {
    parse_from(&bytes)
}

/// [`parse`] against any [`ExecBytes`]. Identical validation, in identical
/// order, so the error a malformed image produces does not depend on whether
/// it was resident or file-backed.
pub fn parse_from<S: ExecBytes + ?Sized>(src: &S) -> Result<ExecImage, ElfError> {
    let image_size = src.size();
    if image_size < 64 {
        return Err(ElfError::TooShort);
    }
    let mut ehdr = [0u8; 64];
    src.read_exact_at(0, &mut ehdr)?;
    let ehdr = &ehdr[..];

    // ELF header identification.
    if ehdr[EI_MAG0] != 0x7F
        || ehdr[EI_MAG1] != b'E'
        || ehdr[EI_MAG2] != b'L'
        || ehdr[EI_MAG3] != b'F'
    {
        return Err(ElfError::BadMagic);
    }
    // ELFCLASS64 is the native class. ELFCLASS32 is an IA-32 program for the
    // compat ABI — on x86_64 only, and only for EM_386/EM_486 (checked
    // below); everything else is not a 64-bit image this kernel runs.
    let class = match ehdr[EI_CLASS] {
        ELFCLASS64 => Class::Elf64,
        ELFCLASS32 => Class::Elf32,
        _ => return Err(ElfError::Not64Bit),
    };
    if ehdr[EI_DATA] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }

    // `e_type` and `e_machine` sit at the same offsets in both classes.
    let e_type = read_u16(ehdr, 0x10);
    let e_machine = read_u16(ehdr, 0x12);
    // `compat_elf_check_arch`: an ELFCLASS32 image is runnable only as an
    // IA-32 program. x32 (ELFCLASS32 EM_X86_64) needs CONFIG_X86_X32_ABI,
    // which NARF does not provide, so it stays `Not64Bit` like any other
    // 32-bit image.
    if class == Class::Elf32 && !compat32_machine(e_machine) {
        return Err(ElfError::Not64Bit);
    }

    let kind = match (e_type, class) {
        (ET_EXEC, Class::Elf64) => ExecKind::Elf64Exec,
        (ET_DYN, Class::Elf64) => ExecKind::Elf64Dyn,
        (ET_EXEC, Class::Elf32) => ExecKind::Elf32Exec,
        (ET_DYN, Class::Elf32) => ExecKind::Elf32Dyn,
        _ => return Err(ElfError::BadType),
    };

    // `e_machine` must match the running architecture. Without this an
    // aarch64 binary loads on x86_64 (and vice versa): the PT_LOADs map,
    // the entry point is a valid mapped address, and the process dies on
    // the first foreign instruction instead of being rejected up front.
    // The module loader already enforces the equivalent for ET_REL.
    if class == Class::Elf64 && e_machine != EM_NATIVE {
        return Err(ElfError::WrongMachine);
    }

    // `Elf64_Ehdr` and `Elf32_Ehdr` diverge from `e_entry` on: the 32-bit
    // header's addresses and offsets are 4 bytes wide.
    let (e_entry, e_phoff, e_phentsize, e_phnum) = match class {
        Class::Elf64 => (
            read_u64(ehdr, 0x18),
            read_u64(ehdr, 0x20),
            read_u16(ehdr, 0x36),
            read_u16(ehdr, 0x38),
        ),
        Class::Elf32 => (
            u64::from(read_u32(ehdr, 0x18)),
            u64::from(read_u32(ehdr, 0x1C)),
            read_u16(ehdr, 0x2A),
            read_u16(ehdr, 0x2C),
        ),
    };

    let phoff = e_phoff as usize;
    let entsize = e_phentsize as usize;
    let phnum = e_phnum as usize;

    // Program-header table sanity, matching Linux's `load_elf_phdrs()`:
    //   * `e_phentsize` must be exactly `sizeof(struct elf_phdr)` for the
    //     class (56 for Elf64, 32 for Elf32). Accepting a larger stride
    //     parses a table shape no toolchain emits and no other loader would
    //     agree with.
    //   * at least one program header, and no more than fit in Linux's
    //     64 KiB table cap — `65536 / 56 == 1170` (2048 for Elf32). This also
    //     keeps the 0xFFFF PN_XNUM sentinel out: Linux does not implement
    //     PN_XNUM for executables either (it is a section-count escape), so a
    //     binary using it is rejected rather than silently mis-parsed.
    let phentsize = class.phentsize();
    let max_phnum = 65536 / phentsize;
    if entsize != phentsize || !(1..=max_phnum).contains(&phnum) {
        return Err(ElfError::BadPhoff);
    }
    let ph_table_end = phoff
        .checked_add(entsize.checked_mul(phnum).ok_or(ElfError::BadPhoff)?)
        .ok_or(ElfError::BadPhoff)?;
    if ph_table_end as u64 > image_size {
        return Err(ElfError::BadPhoff);
    }
    // The table is bounded above by Linux's 64 KiB cap, so reading it whole
    // is bounded work regardless of image size.
    let mut phtab = Vec::new();
    phtab
        .try_reserve_exact(entsize * phnum)
        .map_err(|_| ElfError::BadPhoff)?;
    phtab.resize(entsize * phnum, 0u8);
    src.read_exact_at(e_phoff, &mut phtab)?;

    let mut segments = Vec::new();
    let mut interp: Option<String> = None;
    let mut dynamic: Vec<DynEntry> = Vec::new();
    let mut tls: Option<TlsTemplate> = None;
    let mut stack_flags: Option<SegmentFlags> = None;
    let mut phdr_vaddr: Option<u64> = None;
    let mut property_span: Option<(u64, u64)> = None;
    // Largest power-of-two PT_LOAD alignment, floored at the page size.
    let mut max_align: u64 = 4096;

    for i in 0..phnum {
        let Phdr {
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_filesz,
            p_memsz,
            p_align,
        } = class.phdr(&phtab, i * entsize);

        match p_type {
            PT_LOAD => {
                // A segment cannot carry more file bytes than it has
                // memory bytes to hold them. Linux answers this with
                // EINVAL; NARF previously clamped the page count and
                // silently truncated the copy instead.
                if p_filesz > p_memsz {
                    return Err(ElfError::SegmentFileSizeExceedsMemSize);
                }
                // `maximum_alignment()` in `fs/binfmt_elf.c`: take the largest
                // alignment any PT_LOAD asks for, skipping non-powers-of-two as
                // malformed rather than rejecting the image over them.
                if p_align > max_align && p_align.is_power_of_two() {
                    max_align = p_align;
                }
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
                // entries (16 bytes each; `Elf32_Dyn` is 8). The terminator
                // is DT_NULL (0). We capture every tag here verbatim so the
                // loader (which knows which DT_* it cares about) can match
                // against a flat list rather than re-parsing.
                let end = p_offset
                    .checked_add(p_filesz)
                    .ok_or(ElfError::DynamicOutOfBounds)?;
                if end > image_size {
                    return Err(ElfError::DynamicOutOfBounds);
                }
                let dynsize = class.dynsize();
                if p_filesz % dynsize as u64 != 0 {
                    return Err(ElfError::DynamicOutOfBounds);
                }
                let span = usize::try_from(p_filesz).map_err(|_| ElfError::DynamicOutOfBounds)?;
                let mut buf = Vec::new();
                buf.try_reserve_exact(span)
                    .map_err(|_| ElfError::DynamicOutOfBounds)?;
                buf.resize(span, 0u8);
                src.read_exact_at(p_offset, &mut buf)
                    .map_err(|_| ElfError::DynamicOutOfBounds)?;
                let mut cur = 0usize;
                while cur + dynsize <= span {
                    let (tag, val) = class.dyn_entry(&buf, cur);
                    cur += dynsize;
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
                let end = p_offset
                    .checked_add(p_filesz)
                    .ok_or(ElfError::TlsOutOfBounds)?;
                if end > image_size {
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
                let end = p_offset
                    .checked_add(p_filesz)
                    .ok_or(ElfError::InterpOutOfBounds)?;
                if end > image_size {
                    return Err(ElfError::InterpOutOfBounds);
                }
                let span = usize::try_from(p_filesz).map_err(|_| ElfError::InterpOutOfBounds)?;
                let mut buf = Vec::new();
                buf.try_reserve_exact(span)
                    .map_err(|_| ElfError::InterpOutOfBounds)?;
                buf.resize(span, 0u8);
                src.read_exact_at(p_offset, &mut buf)
                    .map_err(|_| ElfError::InterpOutOfBounds)?;
                // Trim trailing NUL.
                let trimmed = match buf.iter().position(|&b| b == 0) {
                    Some(n) => &buf[..n],
                    None => &buf[..],
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
            PT_PHDR => {
                // The program-header table's own link-time vaddr. This is
                // the authoritative source for AT_PHDR (the loader biases
                // it by the load base): a self-relocating ET_DYN derives
                // its load bias as `AT_PHDR - PT_PHDR.p_vaddr`, so AT_PHDR
                // MUST agree with this header rather than being inferred
                // from PT_LOAD ordering. Capture the raw p_vaddr; the
                // loader adds the bias.
                phdr_vaddr = Some(p_vaddr);
            }
            PT_NOTE => {
                // Not fully implemented, just parsed. Linux consults PT_NOTE
                // for nothing during load either: properties come from
                // PT_GNU_PROPERTY, which is a separate header.
            }
            // Only the native class carries properties NARF enforces. Linux on
            // x86 does not select ARCH_USE_GNU_PROPERTY, so
            // `parse_elf_properties` returns before reading the note for
            // either class; an i386 image's note (4-byte aligned in ELF32)
            // is ignored the same way here.
            PT_GNU_PROPERTY if class == Class::Elf64 => {
                property_span = Some((p_offset, p_filesz));
            }
            _ => { /* other PT_* ignored at this tier */ }
        }
    }

    let properties = match property_span {
        Some((off, size)) => read_gnu_property_segment(src, off, size)?,
        None => ElfProperties::default(),
    };

    Ok(ExecImage {
        kind,
        entry: e_entry,
        interp,
        segments,
        dynamic,
        tls,
        stack_flags,
        phdr_vaddr,
        properties,
        max_align,
        argv: Vec::new(),
        envp: Vec::new(),
        aux: Vec::new(),
    })
}

/// Decode an `NT_GNU_PROPERTY_TYPE_0` note descriptor into [`ElfProperties`].
///
/// Mirrors `parse_elf_property` in `fs/binfmt_elf.c`, including the checks that
/// make a malformed note an error rather than a guess:
///
/// - each record is `pr_type: u32, pr_datasz: u32` followed by `pr_datasz`
///   bytes padded to an 8-byte boundary;
/// - `pr_datasz` must fit the bytes that remain, and so must the padded step,
///   so a record cannot claim data past the end of the note;
/// - records are required to be unique and sorted ascending on `pr_type`
///   ("Properties are supposed to be unique and sorted on pr_type"), which is
///   what stops a second record silently overriding the first.
///
/// Unknown `pr_type`s are skipped, as Linux does — a newer toolchain emitting a
/// property this kernel has no opinion on must not fail the exec.
fn parse_gnu_properties(desc: &[u8]) -> Result<ElfProperties, ElfError> {
    let mut props = ElfProperties::default();
    let mut off = 0usize;
    let mut prev_type: Option<u32> = None;
    while off < desc.len() {
        if off % GNU_PROPERTY_ALIGN != 0 {
            return Err(ElfError::BadGnuProperty);
        }
        let remaining = desc.len() - off;
        if remaining < 8 {
            return Err(ElfError::BadGnuProperty);
        }
        let pr_type = read_u32(desc, off);
        let pr_datasz = read_u32(desc, off + 4) as usize;
        let data_start = off + 8;
        let avail = desc.len() - data_start;
        if pr_datasz > avail {
            return Err(ElfError::BadGnuProperty);
        }
        // Padded stride to the next record; it must also fit, so a final
        // record cannot imply a record past the end.
        let step = pr_datasz.next_multiple_of(GNU_PROPERTY_ALIGN);
        if step > avail {
            return Err(ElfError::BadGnuProperty);
        }
        if prev_type.is_some_and(|prev| pr_type <= prev) {
            return Err(ElfError::BadGnuProperty);
        }
        prev_type = Some(pr_type);

        // Both feature words are `u32` bitmaps. A record with the right type
        // but the wrong size is malformed, not ignorable: it would otherwise
        // read as "no features" and silently disable enforcement.
        let data = &desc[data_start..data_start + pr_datasz];
        match pr_type {
            GNU_PROPERTY_AARCH64_FEATURE_1_AND => {
                if data.len() < 4 {
                    return Err(ElfError::BadGnuProperty);
                }
                let bits = read_u32(data, 0);
                props.aarch64_bti = bits & GNU_PROPERTY_AARCH64_FEATURE_1_BTI != 0;
                props.aarch64_pac = bits & GNU_PROPERTY_AARCH64_FEATURE_1_PAC != 0;
                props.aarch64_mte = bits & GNU_PROPERTY_AARCH64_FEATURE_1_MTE != 0;
            }
            GNU_PROPERTY_X86_FEATURE_1_AND => {
                if data.len() < 4 {
                    return Err(ElfError::BadGnuProperty);
                }
                let bits = read_u32(data, 0);
                props.x86_ibt = bits & GNU_PROPERTY_X86_FEATURE_1_IBT != 0;
                props.x86_shstk = bits & GNU_PROPERTY_X86_FEATURE_1_SHSTK != 0;
            }
            // A property this kernel has no opinion on. Skipping rather than
            // failing keeps a newer toolchain's binaries runnable.
            _ => {}
        }
        off = data_start + step;
    }
    Ok(props)
}

/// Read the `PT_GNU_PROPERTY` segment and decode the one note it may carry.
///
/// The segment holds a standard ELF note: `n_namesz, n_descsz, n_type`, the
/// name padded to 4 bytes, then the descriptor padded to 4. Linux accepts only
/// name `"GNU\0"` with `n_type == NT_GNU_PROPERTY_TYPE_0` and requires the
/// descriptor to be 8-byte aligned for ELF64; anything else is not a property
/// note and yields no properties rather than an error.
fn read_gnu_property_segment<S: ExecBytes + ?Sized>(
    src: &S,
    file_off: u64,
    file_size: u64,
) -> Result<ElfProperties, ElfError> {
    if !(16..=MAX_PROPERTY_BYTES).contains(&file_size) {
        return Err(ElfError::BadGnuProperty);
    }
    let end = file_off
        .checked_add(file_size)
        .ok_or(ElfError::BadGnuProperty)?;
    if end > src.size() {
        return Err(ElfError::BadGnuProperty);
    }
    let mut note = alloc::vec::Vec::new();
    note.try_reserve_exact(file_size as usize)
        .map_err(|_| ElfError::BadGnuProperty)?;
    note.resize(file_size as usize, 0u8);
    src.read_exact_at(file_off, &mut note)?;

    let n_namesz = read_u32(&note, 0) as usize;
    let n_descsz = read_u32(&note, 4) as usize;
    let n_type = read_u32(&note, 8);
    if n_type != NT_GNU_PROPERTY_TYPE_0 || n_namesz != 4 {
        return Ok(ElfProperties::default());
    }
    if note.get(12..16) != Some(b"GNU\0") {
        return Ok(ElfProperties::default());
    }
    // Name is 4 bytes, already 4-aligned; the ELF64 descriptor then starts at
    // an 8-aligned offset, which for this layout is exactly 16.
    let desc_start = 16usize;
    let desc_end = desc_start
        .checked_add(n_descsz)
        .ok_or(ElfError::BadGnuProperty)?;
    if desc_end > note.len() {
        return Err(ElfError::BadGnuProperty);
    }
    parse_gnu_properties(&note[desc_start..desc_end])
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
