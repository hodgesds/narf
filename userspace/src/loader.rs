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
    addr_space: &mut AddressSpace,
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
