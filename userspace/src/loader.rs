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

use crate::{ExecImage, SegmentFlags};

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
