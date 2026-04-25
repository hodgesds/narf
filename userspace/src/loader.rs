//! ELF loader — translate an `ExecImage` into an `AddressSpace`.
//!
//! Spec: `userspace/specification/spec.md`. The real loader:
//!
//! 1. Parses ELF64 headers from a file-backed or in-memory buffer.
//! 2. For each `PT_LOAD` segment: allocate physical frames, copy
//!    `file_size` bytes in, zero `mem_size - file_size` for BSS,
//!    and call `AddressSpace::map_region(base=vaddr, phys, perms)`.
//! 3. If `kind == ExecKind::Elf64Dyn`, apply relocations from
//!    `PT_DYNAMIC`.
//! 4. Allocate a user stack region and push `argv` / `envp` /
//!    `auxv` in the SysV psABI layout.
//!
//! The real ELF parse (step 1) needs a whole `elf` reader we don't
//! carry, and relocation (step 3) is a multi-entry state machine.
//! What we land at this Stage-4 stage is the structural plumbing:
//! `load_into(image, phys_pool, addr_space) -> Result<EntryPoint>`
//! that walks the pre-parsed `ExecImage::segments` and calls
//! `map_region` on each. The per-segment physical frames come from
//! a caller-supplied pool (an iterator of `PhysAddr`); the loader
//! doesn't call the frame allocator directly so tests can hand it a
//! deterministic sequence.

use alloc::sync::Arc;

use narf_memory::{AddressSpace, AddressSpaceError, PhysAddr, Region, RegionPerms, VirtAddr};

use crate::{DynEntry, ExecImage, SegmentFlags};

/// Entry point the loader hands back for the scheduler to branch
/// into once the address space is activated.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EntryPoint(pub VirtAddr);

/// Errors raised during `load_into`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    AddressSpace(AddressSpaceError),
    NoPhysFrames,
    NoSegments,
    BadEntry,
}

impl From<AddressSpaceError> for LoadError {
    fn from(e: AddressSpaceError) -> Self { LoadError::AddressSpace(e) }
}

/// Convert `SegmentFlags` (ELF PF_*) into `RegionPerms`.
fn perms_of(f: SegmentFlags) -> RegionPerms {
    let mut p = RegionPerms::default();
    if f.contains(SegmentFlags::READ)  { p = p | RegionPerms::READ;  }
    if f.contains(SegmentFlags::WRITE) { p = p | RegionPerms::WRITE; }
    if f.contains(SegmentFlags::EXEC)  { p = p | RegionPerms::EXEC;  }
    p
}

/// Walk `image.segments` and install each as a region in
/// `addr_space`. The physical-frame pool is consumed one
/// page-sized frame per page of `mem_size` — Stage-4 structural
/// form is contiguous-frame mapping; the real loader with a
/// scatter list lands when the arch paging primitives do.
pub fn load_into<I>(
    image:      &ExecImage,
    mut phys_pool: I,
    addr_space: &AddressSpace,
) -> Result<EntryPoint, LoadError>
where
    I: Iterator<Item = PhysAddr>,
{
    if image.segments.is_empty() { return Err(LoadError::NoSegments); }
    if image.entry == 0          { return Err(LoadError::BadEntry); }

    for seg in &image.segments {
        // First physical frame for this segment; subsequent pages
        // walk contiguously from it (Stage-4 refinement will use a
        // scatter list).
        let phys = phys_pool.next().ok_or(LoadError::NoPhysFrames)?;
        // Consume additional frames for any pages past the first so
        // the pool is drained correctly — their addresses are
        // implicit given `phys` is contiguous.
        let pages = (seg.mem_size + 0xFFF) >> 12;
        for _ in 1..pages { let _ = phys_pool.next().ok_or(LoadError::NoPhysFrames)?; }

        addr_space.map_region(Region {
            base:  VirtAddr::new(seg.vaddr),
            len:   (pages as u64) << 12,
            perms: perms_of(seg.flags),
            phys,
        })?;
    }

    Ok(EntryPoint(VirtAddr::new(image.entry)))
}

// ── Convenience: `bytes → Arc<AddressSpace>` ───────────────────────

/// Errors that the `load_elf_bytes` end-to-end path can surface.
/// Composes `ElfError` + `LoadError` + frame-allocator failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LoadBytesError {
    Elf(crate::ElfError),
    Load(LoadError),
    NoFrame,
    ByteCopyOutOfBounds,
    /// PT_DYNAMIC named a relocation table whose file-region
    /// pointers (DT_RELA / DT_JMPREL) couldn't be located in the
    /// ELF bytes — typically because the dynamic-linker fixed
    /// in-memory addresses aren't covered by any PT_LOAD's file
    /// span, so we can't read the entries.
    RelaOutOfBounds,
    /// Encountered a relocation type we don't implement yet
    /// (anything outside R_X86_64_RELATIVE / _64 / _GLOB_DAT /
    /// _JUMP_SLOT) or a relocation that needs symbol resolution
    /// (which the Stage-4 first cut hasn't wired up).
    UnsupportedRelocation,
    /// A relocation's `r_offset` (after `vaddr_bias`) isn't backed
    /// by a materialised page in the address space, so we can't
    /// reach the patch site.
    RelocTargetUnmapped,
    /// A symbol-resolved relocation (R_X86_64_64 / GLOB_DAT /
    /// JUMP_SLOT) named a sym_idx whose `Elf64_Sym` slot has
    /// `st_value == 0 && st_shndx == SHN_UNDEF (0)` — i.e. the
    /// symbol is declared but not defined in this image. External
    /// symbol resolution is out of scope until a host-provided
    /// resolver lands; the loader walks DT_STRTAB so callers see
    /// the symbol *name* alongside the index, which is what they
    /// actually need to diagnose "where did this come from?".
    ///
    /// `name` holds the first 32 bytes of the NUL-terminated
    /// symbol string captured from DT_STRTAB, NUL-padded if the
    /// name is shorter and truncated if longer. An all-zero buffer
    /// means lookup failed (DT_STRTAB missing, `st_name == 0`, or
    /// the offset walked past any PT_LOAD segment).
    UnresolvedSymbol {
        idx:  u32,
        name: [u8; 32],
    },
    /// A symbol-resolved relocation referenced a sym_idx whose
    /// `Elf64_Sym` slot at `DT_SYMTAB + sym_idx * 24` lies outside
    /// any PT_LOAD segment's file region — either DT_SYMTAB itself
    /// is missing or the index walks past the table's tail.
    SymtabOutOfBounds,
}

impl From<crate::ElfError> for LoadBytesError {
    fn from(e: crate::ElfError) -> Self { LoadBytesError::Elf(e) }
}
impl From<LoadError> for LoadBytesError {
    fn from(e: LoadError) -> Self { LoadBytesError::Load(e) }
}

/// Parse ELF `bytes`, allocate fresh frames for every `PT_LOAD`
/// segment, copy bytes in, and push regions onto the existing
/// `addr_space` with each segment's vaddr biased by `vaddr_bias`.
/// Returns the (biased) entry point. Does NOT call `materialize` —
/// the caller batches a single materialize call after every image
/// has been staged so PT_INTERP can share an AS with the program.
///
/// `vaddr_bias = 0` reproduces the historical behaviour for an
/// `ET_EXEC` program; non-zero biases place a `PT_DYN` interpreter
/// (or PIE program) at a chosen base.
///
/// # Safety
/// Same identity-mapping + frame-allocator contract as
/// [`load_elf_bytes`].
pub unsafe fn load_elf_into_at(
    bytes:      &[u8],
    addr_space: &AddressSpace,
    vaddr_bias: u64,
) -> Result<u64, LoadBytesError> {
    let image = crate::parse_elf(bytes)?;
    if image.segments.is_empty() { return Err(LoadBytesError::Load(LoadError::NoSegments)); }
    if image.entry == 0          { return Err(LoadBytesError::Load(LoadError::BadEntry)); }

    // Allocate all needed frames up front, chunk by chunk.
    let mut allocated: alloc::vec::Vec<PhysAddr> = alloc::vec::Vec::new();
    for seg in &image.segments {
        let pages = (seg.mem_size + 0xFFF) >> 12;
        for _ in 0..pages {
            let f = narf_memory::alloc_frame().map_err(|_| LoadBytesError::NoFrame)?;
            allocated.push(f.start_address());
        }
    }

    // Zero every allocated frame before we copy into it (so the
    // `mem_size > file_size` BSS tail is naturally zero).
    for &p in &allocated {
        // SAFETY: identity-mapped in low 4 GiB.
        unsafe {
            core::ptr::write_bytes(p.raw() as *mut u8, 0, 4096);
        }
    }

    // Push regions, mirroring `load_into` but with the bias applied
    // to each segment's base vaddr.
    let mut pool = allocated.iter().copied();
    for seg in &image.segments {
        let first = pool.next().ok_or(LoadBytesError::NoFrame)?;
        let pages = (seg.mem_size + 0xFFF) >> 12;
        for _ in 1..pages { let _ = pool.next().ok_or(LoadBytesError::NoFrame)?; }

        addr_space.map_region(Region {
            base:  VirtAddr::new(seg.vaddr.wrapping_add(vaddr_bias)),
            len:   (pages as u64) << 12,
            perms: perms_of(seg.flags),
            phys:  first,
        }).map_err(|e| LoadBytesError::Load(LoadError::AddressSpace(e)))?;
    }

    // Copy segment data. Re-walk the pool in identical consumption
    // order so each segment finds the frames it just got mapped to.
    let mut pool = allocated.iter().copied();
    for seg in &image.segments {
        let first = pool.next().ok_or(LoadBytesError::NoFrame)?;
        let pages = (seg.mem_size + 0xFFF) >> 12;
        for _ in 1..pages { let _ = pool.next(); }

        let start = seg.file_off as usize;
        let end   = start.checked_add(seg.file_size as usize)
            .ok_or(LoadBytesError::ByteCopyOutOfBounds)?;
        if end > bytes.len() {
            return Err(LoadBytesError::ByteCopyOutOfBounds);
        }
        let src = &bytes[start..end];
        // SAFETY: allocated frames are identity-mapped; we write
        // within the total size we allocated.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                first.raw() as *mut u8,
                src.len(),
            );
        }
    }

    Ok(image.entry.wrapping_add(vaddr_bias))
}

/// One-shot: parse ELF bytes, allocate a fresh user `AddressSpace`,
/// map + materialize every `PT_LOAD` segment, and copy the segment
/// data from `bytes` into the backing physical frames. Returns the
/// `Arc<AddressSpace>` ready to attach to a `spawn_user` task, plus
/// the entry point.
///
/// BSS (the `mem_size > file_size` tail) is zero — frames come from
/// the allocator freshly-zeroed.
///
/// # Safety
/// - `bytes` must be a live slice for the duration of this call.
/// - The kernel must be running with the low 4 GiB identity-mapped
///   so `phys.raw() as *mut u8` writes reach the backing storage.
/// - Frame allocator must be initialised.
pub unsafe fn load_elf_bytes(
    bytes: &[u8],
) -> Result<(Arc<AddressSpace>, EntryPoint), LoadBytesError> {
    // SAFETY: `new_for_user` contract — caller is in kernel mode
    // with paging up.
    let addr_space = unsafe { AddressSpace::new_for_user() }
        .map_err(|e| LoadBytesError::Load(LoadError::AddressSpace(e)))?;

    // SAFETY: forwarding the caller's identity-map + allocator
    // contract; bias 0 keeps historical behaviour for ET_EXEC.
    let entry = unsafe { load_elf_into_at(bytes, &addr_space, 0) }?;

    // Install PTEs.
    // SAFETY: AS constructed by `new_for_user`; regions just pushed
    // via `load_elf_into_at`.
    unsafe { addr_space.materialize() }
        .map_err(|e| LoadBytesError::Load(LoadError::AddressSpace(e)))?;

    Ok((Arc::new(addr_space), EntryPoint(VirtAddr::new(entry))))
}

// ── PT_DYNAMIC relocation processing ────────────────────────────────
//
// PIE programs and dynamic libraries record relocations in the
// `.rela.dyn` (covering data + GOT slots) and `.rela.plt` (covering
// PLT jump slots) sections. PT_DYNAMIC's DT_RELA / DT_RELASZ and
// DT_JMPREL / DT_PLTRELSZ tags name the in-memory addresses + sizes
// of those tables; the linker's ld.so walks them and patches each
// `r_offset` site.
//
// This first cut handles R_X86_64_RELATIVE end-to-end (the only
// relocation a self-contained PIE actually needs — it expresses
// "add the load bias to this slot") and refuses everything else
// with `LoadBytesError::UnsupportedRelocation`. Symbol-resolving
// relocations (R_X86_64_64 / GLOB_DAT / JUMP_SLOT) need a symbol
// table and string table; we lay the parsing groundwork here so a
// later round just plugs in `resolve_symbol`.

// DT_* tag wire constants we care about. The "currently-unused"
// SYMTAB/STRTAB/STRSZ/RELACOUNT entries are kept here so the
// follow-up symbol-resolution pass can pick them up without
// re-deriving the wire numbers.
const DT_PLTRELSZ:   i64 = 2;
// DT_STRTAB drives symbol-name lookup for the unresolved-import
// path: when an external symbol triggers `UnresolvedSymbol`, we
// follow `st_name` into the string table so the error carries a
// name (truncated to 32 bytes), not just an opaque sym_idx.
const DT_STRTAB:     i64 = 5;
const DT_SYMTAB:     i64 = 6;
const DT_RELA:       i64 = 7;
const DT_RELASZ:     i64 = 8;
const DT_RELAENT:    i64 = 9;
#[allow(dead_code)] const DT_STRSZ:  i64 = 10;
const DT_PLTREL:     i64 = 20;
const DT_JMPREL:     i64 = 23;
#[allow(dead_code)] const DT_RELACOUNT: i64 = 0x6FFFFFF9;

/// `sizeof(Elf64_Sym)` per the ELF64 ABI:
/// `{ st_name: u32, st_info: u8, st_other: u8, st_shndx: u16,
///    st_value: u64, st_size: u64 }`.
const ELF64_SYM_SIZE: u64 = 24;
/// `SHN_UNDEF` — the section index meaning "this symbol isn't
/// defined here". Combined with `st_value == 0` it identifies a
/// purely-external symbol; non-zero `st_shndx` means defined-in-image.
const SHN_UNDEF: u16 = 0;

// x86_64 relocation type codes (low 32 bits of `r_info`).
const R_X86_64_64:        u32 = 1;
const R_X86_64_GLOB_DAT:  u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE:  u32 = 8;

/// Lookup helper — return the value paired with the *first*
/// occurrence of `tag` in `dynamic`. PT_DYNAMIC duplicates would
/// be malformed; we treat first-wins as the spec does.
fn dt_lookup(dynamic: &[DynEntry], tag: i64) -> Option<u64> {
    dynamic.iter().find(|e| e.tag == tag).map(|e| e.val)
}

/// Translate a DT_* in-memory address to a slice of the input ELF
/// bytes. The dynamic-linker tables (DT_RELA / DT_JMPREL pointers)
/// are recorded as the *vaddr* the linker assigned them at link
/// time; we resolve them back to file offsets by matching against
/// each PT_LOAD's `[vaddr, vaddr + file_size)` span and applying
/// the same `(file_off - vaddr)` translation.
fn resolve_dt_pointer<'a>(
    bytes: &'a [u8],
    image: &ExecImage,
    dt_addr: u64,
    needed: u64,
) -> Option<&'a [u8]> {
    for seg in &image.segments {
        // A DT_* pointer is in-bounds for a segment when it lies in
        // [vaddr, vaddr + file_size). file_size (not mem_size) is the
        // right ceiling because relocation tables are file-resident.
        if dt_addr < seg.vaddr { continue; }
        let off_in_seg = dt_addr - seg.vaddr;
        if off_in_seg >= seg.file_size { continue; }
        let avail = seg.file_size - off_in_seg;
        if avail < needed { return None; }
        let file_start = (seg.file_off + off_in_seg) as usize;
        let file_end   = file_start.checked_add(needed as usize)?;
        if file_end > bytes.len() { return None; }
        return Some(&bytes[file_start..file_end]);
    }
    None
}

#[inline]
fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Resolve a user vaddr (after `vaddr_bias`) to a kernel-writable
/// pointer through the active address space. Mirrors
/// `process::resolve_user_phys_byte` so the relocation processor
/// can reach freshly-materialised pages without depending on the
/// stack-init code path.
#[cfg(target_arch = "x86_64")]
fn user_vaddr_to_kernel_ptr(addr_space: &AddressSpace, vaddr: u64) -> Option<*mut u8> {
    let page = vaddr & !0xFFFu64;
    let off  = vaddr & 0xFFFu64;
    let p = unsafe {
        narf_memory::x86_64::paging::translate(addr_space.root, VirtAddr::new(page))
    }?;
    Some((p.as_u64() + off) as *mut u8)
}

#[cfg(not(target_arch = "x86_64"))]
fn user_vaddr_to_kernel_ptr(_addr_space: &AddressSpace, _vaddr: u64) -> Option<*mut u8> {
    // aarch64 paging::translate isn't wired in narf-memory yet, same
    // story as `init_sysv_stack`. Relocation is x86_64-only at this
    // tier; arches without translate fall through and return None,
    // which the caller surfaces as `RelocTargetUnmapped`.
    None
}

/// Resolve an `Elf64_Sym` index against `DT_SYMTAB` to a runtime
/// (biased) virtual address.
///
/// The symbol table has no `DT_SYMSZ` in the standard tags — its
/// length is implicit, derived from the largest sym_idx used by any
/// relocation. We don't know that bound up front, so we read the
/// `Elf64_Sym` directly at `DT_SYMTAB + sym_idx * 24` and require
/// the read to land inside a PT_LOAD segment's file region (via
/// `resolve_dt_pointer`); if it doesn't, the index is out of bounds.
///
/// Internal symbol policy:
/// - `st_shndx == SHN_UNDEF (0)` and `st_value == 0`: declared but
///   not defined — external. Returns `UnresolvedSymbol`.
/// - Otherwise: defined-in-image. Returns `st_value + vaddr_bias`.
///
/// String-table walking (DT_STRTAB / DT_STRSZ) is intentionally not
/// performed: this round only resolves internally-defined symbols
/// where sym_idx is sufficient. External symbol resolution needs
/// `st_name → string table → host resolver` and lands later.
fn resolve_symbol(
    bytes:      &[u8],
    image:      &ExecImage,
    sym_idx:    u32,
    vaddr_bias: u64,
) -> Result<u64, LoadBytesError> {
    let symtab_addr = dt_lookup(&image.dynamic, DT_SYMTAB)
        .ok_or(LoadBytesError::SymtabOutOfBounds)?;
    let entry_addr = symtab_addr
        .checked_add((sym_idx as u64).checked_mul(ELF64_SYM_SIZE)
            .ok_or(LoadBytesError::SymtabOutOfBounds)?)
        .ok_or(LoadBytesError::SymtabOutOfBounds)?;
    let slice = resolve_dt_pointer(bytes, image, entry_addr, ELF64_SYM_SIZE)
        .ok_or(LoadBytesError::SymtabOutOfBounds)?;

    // Layout: st_name(4) | st_info(1) | st_other(1) | st_shndx(2)
    //       | st_value(8) | st_size(8).
    let st_shndx = u16::from_le_bytes([slice[6], slice[7]]);
    let st_value = read_u64_le(&slice[8..16]);

    if st_value == 0 && st_shndx == SHN_UNDEF {
        let name = resolve_symbol_name(bytes, image, sym_idx);
        return Err(LoadBytesError::UnresolvedSymbol { idx: sym_idx, name });
    }
    Ok(st_value.wrapping_add(vaddr_bias))
}

/// Best-effort lookup of an `Elf64_Sym`'s name through DT_STRTAB.
/// Returns a fixed 32-byte buffer holding the NUL-terminated name's
/// leading bytes (NUL-padded if shorter than 32, truncated if longer).
///
/// Returns the all-zero buffer when:
/// - `DT_SYMTAB` is missing or the sym_idx walks off any PT_LOAD,
/// - `DT_STRTAB` is missing (no string-table pointer),
/// - `st_name == 0` (SysV's "no name" convention — the strtab's
///   leading byte is reserved as the empty string),
/// - the strtab offset walks off any PT_LOAD segment.
///
/// The fixed-size buffer keeps the loader path alloc-free; the
/// 32-byte cap is sized for typical libc symbols (`printf`, `malloc`,
/// `__libc_start_main`) and documented as truncating for longer ones.
fn resolve_symbol_name(
    bytes:   &[u8],
    image:   &ExecImage,
    sym_idx: u32,
) -> [u8; 32] {
    let empty = [0u8; 32];

    // Walk to the Elf64_Sym slot to read st_name. We mirror
    // `resolve_symbol`'s arithmetic but swallow any failure into the
    // empty buffer — name lookup is best-effort.
    let symtab_addr = match dt_lookup(&image.dynamic, DT_SYMTAB) {
        Some(a) => a,
        None    => return empty,
    };
    let entry_addr = match (sym_idx as u64)
        .checked_mul(ELF64_SYM_SIZE)
        .and_then(|off| symtab_addr.checked_add(off))
    {
        Some(a) => a,
        None    => return empty,
    };
    let sym_slice = match resolve_dt_pointer(bytes, image, entry_addr, ELF64_SYM_SIZE) {
        Some(s) => s,
        None    => return empty,
    };
    let st_name = u32::from_le_bytes([sym_slice[0], sym_slice[1], sym_slice[2], sym_slice[3]]);
    // st_name == 0 → SysV "no name" convention; strtab[0] is the
    // canonical empty string and we treat it the same as missing.
    if st_name == 0 { return empty; }

    let strtab_addr = match dt_lookup(&image.dynamic, DT_STRTAB) {
        Some(a) => a,
        None    => return empty,
    };
    let name_addr = match strtab_addr.checked_add(st_name as u64) {
        Some(a) => a,
        None    => return empty,
    };

    // We don't know the symbol-name length up front, and
    // `resolve_dt_pointer` rejects reads that would walk off a
    // segment's tail. Try the maximum 32-byte read first; if the
    // strtab tail leaves fewer bytes available, shrink the request
    // until it fits — this is at most 32 attempts so the cost is
    // bounded. Once we have a slice, scan for the NUL terminator
    // and copy the prefix.
    let mut out = [0u8; 32];
    for cap in (1u64..=32).rev() {
        if let Some(s) = resolve_dt_pointer(bytes, image, name_addr, cap) {
            for (i, &b) in s.iter().enumerate() {
                // Stop on NUL: terminator is not part of the name,
                // and the buffer's already pre-zeroed so the trailing
                // bytes naturally NUL-pad.
                if b == 0 { return out; }
                out[i] = b;
            }
            return out;
        }
    }
    empty
}

/// Walk DT_RELA + DT_JMPREL and patch each entry.
///
/// `vaddr_bias` is the load offset applied to PT_LOAD vaddrs and
/// to R_X86_64_RELATIVE addends — `0` for an ET_EXEC program,
/// non-zero for an ET_DYN interpreter loaded at a chosen base.
///
/// # Safety
/// - `addr_space` must already be `materialize()`-d so each
///   relocated `r_offset` is reachable through the AS.
/// - The kernel must be running with the low 4 GiB identity-mapped
///   (we write through `paging::translate`'s phys output cast to a
///   raw pointer).
pub unsafe fn apply_relocations(
    bytes:      &[u8],
    image:      &ExecImage,
    addr_space: &AddressSpace,
    vaddr_bias: u64,
) -> Result<(), LoadBytesError> {
    if image.dynamic.is_empty() { return Ok(()); }

    // DT_RELA — the .rela.dyn array.
    if let Some(rela_addr) = dt_lookup(&image.dynamic, DT_RELA) {
        let relasz = dt_lookup(&image.dynamic, DT_RELASZ).unwrap_or(0);
        let relaent = dt_lookup(&image.dynamic, DT_RELAENT).unwrap_or(24);
        // DT_RELACOUNT, when present, is authoritative for the count
        // of *contiguous R_X86_64_RELATIVE entries at the start of
        // the array* (linker emits them in a block to allow a fast
        // path). When absent we fall back to RELASZ/RELAENT.
        let count = if relaent != 0 { relasz / relaent } else { 0 };
        if count > 0 {
            let needed = count.checked_mul(relaent).ok_or(LoadBytesError::RelaOutOfBounds)?;
            let slice  = resolve_dt_pointer(bytes, image, rela_addr, needed)
                .ok_or(LoadBytesError::RelaOutOfBounds)?;
            unsafe {
                process_rela_array(slice, count as usize, relaent as usize,
                                   bytes, image, addr_space, vaddr_bias)?;
            }
        }
    }

    // DT_JMPREL — the .rela.plt array. We only walk it if DT_PLTREL
    // signals RELA-format entries (DT_PLTREL == DT_RELA); REL-format
    // doesn't appear on x86_64 in practice.
    if let Some(jmprel_addr) = dt_lookup(&image.dynamic, DT_JMPREL) {
        let pltrel = dt_lookup(&image.dynamic, DT_PLTREL).unwrap_or(0) as i64;
        if pltrel == DT_RELA {
            let pltrelsz = dt_lookup(&image.dynamic, DT_PLTRELSZ).unwrap_or(0);
            let relaent  = dt_lookup(&image.dynamic, DT_RELAENT).unwrap_or(24);
            let count = if relaent != 0 { pltrelsz / relaent } else { 0 };
            if count > 0 {
                let needed = count.checked_mul(relaent).ok_or(LoadBytesError::RelaOutOfBounds)?;
                let slice  = resolve_dt_pointer(bytes, image, jmprel_addr, needed)
                    .ok_or(LoadBytesError::RelaOutOfBounds)?;
                unsafe {
                    process_rela_array(slice, count as usize, relaent as usize,
                                       bytes, image, addr_space, vaddr_bias)?;
                }
            }
        } else if pltrel != 0 {
            // DT_REL-format PLT relocations aren't implemented.
            return Err(LoadBytesError::UnsupportedRelocation);
        }
    }

    Ok(())
}

/// Iterate `Elf64_Rela { r_offset, r_info, r_addend }` entries and
/// patch each one. Encapsulated so DT_RELA + DT_JMPREL can share
/// the per-entry decoding without duplicating the loop.
unsafe fn process_rela_array(
    slice:      &[u8],
    count:      usize,
    entsize:    usize,
    bytes:      &[u8],
    image:      &ExecImage,
    addr_space: &AddressSpace,
    vaddr_bias: u64,
) -> Result<(), LoadBytesError> {
    if entsize < 24 { return Err(LoadBytesError::RelaOutOfBounds); }
    if slice.len() < count.checked_mul(entsize).ok_or(LoadBytesError::RelaOutOfBounds)? {
        return Err(LoadBytesError::RelaOutOfBounds);
    }

    for i in 0..count {
        let off = i * entsize;
        let r_offset = read_u64_le(&slice[off       .. off + 8]);
        let r_info   = read_u64_le(&slice[off + 8   .. off + 16]);
        let r_addend = read_u64_le(&slice[off + 16  .. off + 24]) as i64;

        let rtype  = (r_info & 0xFFFF_FFFF) as u32;
        let sym_ix = (r_info >> 32) as u32;

        // Compute the value we'll write.
        let value: u64 = match rtype {
            R_X86_64_RELATIVE => {
                // S = 0 (no symbol). Result = B + A, where B is the
                // load bias we're applying and A is r_addend.
                vaddr_bias.wrapping_add(r_addend as u64)
            }
            R_X86_64_64 => {
                // S + A — symbol address (biased) plus addend.
                let s = resolve_symbol(bytes, image, sym_ix, vaddr_bias)?;
                s.wrapping_add(r_addend as u64)
            }
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                // S — bare symbol address. The addend slot is reserved
                // by the ABI for these two types; ignore it.
                resolve_symbol(bytes, image, sym_ix, vaddr_bias)?
            }
            _ => return Err(LoadBytesError::UnsupportedRelocation),
        };

        // Patch site. r_offset is the link-time vaddr of the slot;
        // for a PIE we add `vaddr_bias` to land in the runtime image.
        let target_va = r_offset.wrapping_add(vaddr_bias);
        let dst = user_vaddr_to_kernel_ptr(addr_space, target_va)
            .ok_or(LoadBytesError::RelocTargetUnmapped)?;
        // SAFETY: dst points into an identity-mapped phys frame
        // backing the user's mapped page; the slot is 8 bytes wide
        // and aligned by construction (linker emits 8-aligned r_offsets
        // for R_X86_64_64-class relocations).
        unsafe { core::ptr::write_unaligned(dst as *mut u64, value); }
    }

    Ok(())
}
