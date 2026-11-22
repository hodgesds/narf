//! Per-address-space IA-32 state: what `load_elf_binary` decides for an
//! ELFCLASS32 image and later syscalls consult.
//!
//! Linux keeps these in `mm_struct` (`start_brk`) and in the exec-time
//! personality (`elf_read_implies_exec`). NARF's `AddressSpace` carries the
//! layout itself (`AddressSpace::is_compat32_layout`); the remaining facts
//! live here, keyed by `AddressSpace::identity()` like the other per-mm side
//! tables (pkeys, mbind ranges, seals): created by the loader, copied at fork
//! (`fork_mapped_file_address_space`) and dropped with the address space
//! (`drop_mapped_file_address_space`).

use alloc::collections::BTreeMap;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::AddressSpace;

use crate::ExecImage;

/// `ELF_ET_DYN_BASE` for `mmap_is_ia32()` (`arch/x86/include/asm/elf.h`):
/// where an i386 PIE is loaded, and where the break of a loader run as the
/// program starts.
pub const ET_DYN_BASE: u64 = 0x0040_0000;

/// The IA-32 facts of one address space.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompatMm {
    /// `mm->start_brk`: the lowest program break, where `brk(2)` grows from.
    pub start_brk: u64,
    /// `elf_read_implies_exec` held for the image: an IA-32 binary with no
    /// `PT_GNU_STACK` (`EXSTACK_DEFAULT`) runs with `READ_IMPLIES_EXEC`.
    pub read_implies_exec: bool,
}

static COMPAT_MM: IrqSafeSpinLock<Option<BTreeMap<u64, CompatMm>>> = IrqSafeSpinLock::new(None);

/// Record `mm` for the address space `as_id`, replacing any earlier entry.
pub fn register(as_id: u64, mm: CompatMm) {
    COMPAT_MM
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(as_id, mm);
}

/// The IA-32 facts of `as_id`, if it was loaded for an i386 image.
pub fn lookup(as_id: u64) -> Option<CompatMm> {
    COMPAT_MM.lock().as_ref()?.get(&as_id).copied()
}

/// `dup_mm`: a forked address space keeps its parent's `start_brk`.
pub fn fork(parent_id: u64, child_id: u64) {
    let mut g = COMPAT_MM.lock();
    if let Some(map) = g.as_mut() {
        if let Some(mm) = map.get(&parent_id).copied() {
            map.insert(child_id, mm);
        }
    }
}

/// The entry dies with its address space.
pub fn drop_mm(as_id: u64) {
    if let Some(map) = COMPAT_MM.lock().as_mut() {
        map.remove(&as_id);
    }
}

/// `load_elf_binary`'s `mm->start_brk` for an IA-32 image loaded with
/// `program_bias`:
///
/// ```text
/// if (... elf_ex->e_type == ET_DYN && !interpreter) {
///         elf_brk = ELF_ET_DYN_BASE;      /* a loader run directly */
///         brk_moved = true;
/// }
/// mm->start_brk = mm->brk = ELF_PAGEALIGN(elf_brk);
/// if ((current->flags & PF_RANDOMIZE) && snapshot_randomize_va_space > 1) {
///         if (!brk_moved)
///                 mm->brk = mm->start_brk = mm->brk + PAGE_SIZE;
///         mm->brk = mm->start_brk = arch_randomize_brk(mm);
/// }
/// ```
///
/// `elf_brk` is the end of the highest PT_LOAD's memory image. The
/// randomization is NARF's user-image slot (a page-granular offset of up to
/// 16 MiB, never zero, so it also supplies the one-page gap) in place of
/// `arch_randomize_brk`'s 32 MiB `randomize_page` for a 32-bit task.
pub fn start_brk(image: &ExecImage, program_bias: u64) -> u64 {
    let loader_run_directly = image.kind.is_dyn() && image.interp.is_none();
    let base = if loader_run_directly {
        ET_DYN_BASE
    } else {
        let elf_brk = image
            .segments
            .iter()
            .map(|seg| {
                seg.vaddr
                    .wrapping_add(program_bias)
                    .saturating_add(seg.mem_size)
            })
            .max()
            .unwrap_or(ET_DYN_BASE);
        elf_brk.saturating_add(0xFFF) & !0xFFF
    };
    if crate::handlers::randomize_user_layout() {
        narf_memory::kaslr::user_elf_slot(base)
    } else {
        base
    }
}

/// `[start_brk, ceiling)` for an IA-32 address space's heap: from the
/// loader-recorded `start_brk` up to the compat mmap floor (the bottom-up
/// mmap region, which starts with the interpreter). An IA-32 layout the
/// loader never registered (a hand-built test address space) gets an empty
/// arena rather than one in the 64-bit heap window its pointers cannot reach.
pub fn brk_arena(as_ref: &AddressSpace) -> (u64, u64) {
    let ceiling = as_ref.mmap_floor();
    match lookup(as_ref.identity()) {
        Some(mm) if mm.start_brk < ceiling => (mm.start_brk, ceiling),
        _ => (ceiling, ceiling),
    }
}
