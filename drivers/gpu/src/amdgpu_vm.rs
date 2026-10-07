//! GPU virtual memory for GMC 11 — `amdgpu_vm.c`, `amdgpu_vm_pt.c`,
//! `gmc_v11_0.c`.
//!
//! Two things live here: the **address-space geometry** (how a GPU virtual
//! address decomposes into page-table indices) and the **page-table entry
//! encoding** (what a PTE's bits mean). Both are hardware contracts with no
//! room for approximation — a wrong index walks the GPU into someone else's
//! page table, and a wrong permission bit is the difference between a buffer a
//! shader may write and one it may not.
//!
//! None of it is guessed. Every number is derived the way `amdgpu_vm.c`
//! derives it, from the one call `gmc_v11_0.c` makes:
//!
//! ```text
//! amdgpu_vm_adjust_size(adev, 256 * 1024, 9, 3, 48);
//! //                          min_vm_size  ^  ^  ^ max_bits
//! //                          fragment_size_default
//! //                                          max_level
//! ```
//!
//! which resolves, for every GMC 11 part, to a 256 TiB address space over four
//! levels of 512 entries — see [`Geometry::GMC11`] for the arithmetic.
//!
//! ## What this module does not do yet
//!
//! LINUX-GAP: page tables are **described, not materialised**. There is no
//! per-context VM object, so nothing allocates a root page directory, writes
//! PDEs and PTEs into it, or invalidates the TLB. That needs `AMDGPU_CTX` and
//! the VM-hub invalidation sequence, and it is the next piece. What exists is
//! the layer every part of that will be written against, plus `AMDGPU_GEM_VA`'s
//! validation and bookkeeping — so a client's mapping requests are accepted,
//! checked and recorded, and the addresses it is told it has are addresses the
//! hardware could actually be programmed with.
//!
//! LINUX-GAP: `AMDGPU_VM_PAGE_PRT` (partially-resident textures) is validated
//! but refused. PRT maps a range with no backing at all and relies on the
//! `PRT`/`TF` PTE bits to fault gracefully; it is a sparse-residency feature no
//! client needs before basic submission works.
//!
//! LINUX-GAP: `AMDGPU_VM_DELAY_UPDATE` is accepted and ignored. It asks the
//! kernel to batch the page-table write until the next submission, and with no
//! page-table writes at all there is nothing to defer.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_uapi as uapi;
use crate::drm_ioctl_bridge::copy_in;
use crate::drm_uapi;

/// `AMDGPU_GPU_PAGE_SHIFT` / `AMDGPU_GPU_PAGE_SIZE`.
pub const GPU_PAGE_SHIFT: u32 = 12;
pub const GPU_PAGE_SIZE: u64 = 1 << GPU_PAGE_SHIFT;

// ── PTE and PDE bits (`amdgpu_vm.h`) ────────────────────────────────────

pub const PTE_VALID: u64 = 1 << 0;
/// The page lives in system memory rather than VRAM.
pub const PTE_SYSTEM: u64 = 1 << 1;
/// CPU caches are snooped for this page.
pub const PTE_SNOOPED: u64 = 1 << 2;
pub const PTE_TMZ: u64 = 1 << 3;
pub const PTE_EXECUTABLE: u64 = 1 << 4;
pub const PTE_READABLE: u64 = 1 << 5;
pub const PTE_WRITEABLE: u64 = 1 << 6;
/// `AMDGPU_PTE_PRT` — a partially-resident entry.
pub const PTE_PRT: u64 = 1 << 51;
/// `AMDGPU_PDE_PTE` — this directory entry is a leaf, mapping a huge page
/// directly instead of pointing at the next level.
pub const PDE_PTE: u64 = 1 << 54;
pub const PTE_LOG: u64 = 1 << 55;
/// Translate-further: fault instead of translating.
pub const PTE_TF: u64 = 1 << 56;
/// Do not allocate in the MALL (infinity cache).
pub const PTE_NOALLOC: u64 = 1 << 58;

/// `AMDGPU_PTE_FRAG(x)` — the fragment size, as a page-count log2.
pub const fn pte_frag(x: u64) -> u64 {
    (x & 0x1f) << 7
}

/// `AMDGPU_PDE_BFS(a)` — a directory's block-fragment size.
pub const fn pde_bfs(a: u64) -> u64 {
    a << 59
}

/// `AMDGPU_PTE_MTYPE_NV10` — the memory type, at bits 50:48 on GFX10/11.
///
/// GFX9 put it at 58:57 and GFX12 at 55:54, which is why Linux has three
/// separate macros; using the wrong one silently writes into neighbouring
/// fields (`NOALLOC` sits at 58).
pub const MTYPE_SHIFT: u32 = 48;
pub const MTYPE_MASK: u64 = 7 << MTYPE_SHIFT;

/// `MTYPE_*` from `navi10_enum.h`.
pub const MTYPE_NC: u64 = 0;
pub const MTYPE_WC: u64 = 1;
pub const MTYPE_CC: u64 = 2;
pub const MTYPE_UC: u64 = 3;

/// `AMDGPU_PTE_MTYPE_NV10(flags, mtype)`: clear the field, then set it.
pub const fn with_mtype(flags: u64, mtype: u64) -> u64 {
    (flags & !MTYPE_MASK) | ((mtype << MTYPE_SHIFT) & MTYPE_MASK)
}

// ── Address-space geometry ──────────────────────────────────────────────

/// Page-table level, outermost first. `amdgpu_vm.h`'s
/// `AMDGPU_VM_PDB3 .. AMDGPU_VM_PTB`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Pdb3 = 0,
    Pdb2 = 1,
    Pdb1 = 2,
    Pdb0 = 3,
    Ptb = 4,
}

impl Level {
    const ALL: [Level; 5] = [
        Level::Pdb3,
        Level::Pdb2,
        Level::Pdb1,
        Level::Pdb0,
        Level::Ptb,
    ];
}

/// The VM layout one ASIC family presents.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// `vm_manager.max_pfn` — one past the last mappable GPU page.
    pub max_pfn: u64,
    /// `vm_manager.root_level`.
    pub root_level: Level,
    /// `vm_manager.block_size` — log2 of the leaf table's entry count.
    pub block_size: u32,
    /// `vm_manager.fragment_size`.
    pub fragment_size: u32,
}

impl Geometry {
    /// Every GMC 11 part, from `gmc_v11_0_sw_init`'s
    /// `amdgpu_vm_adjust_size(adev, 256 * 1024, 9, 3, 48)`.
    ///
    /// Worked through as `amdgpu_vm_adjust_size` does it:
    ///
    /// ```text
    /// max_size   = 1 << (48 - 30)          = 262144 GiB
    /// vm_size    = clamp(.., 256*1024, max_size)
    ///            = 262144 GiB              (min == max, so no RAM dependence)
    /// max_pfn    = vm_size << 18           = 2^36 pages = 256 TiB
    /// tmp        = roundup_pow_of_two(2^36) = 2^36
    /// num_level  = min(3, ceil((fls64(2^36) - 1) / 9) - 1)
    ///            = min(3, ceil(36/9) - 1)  = min(3, 3) = 3
    /// root_level = PDB2                     (num_level == 3)
    /// block_size = 9                        (num_level > 1)
    /// ```
    ///
    /// So: PDB2 → PDB1 → PDB0 → PTB, 512 entries each, 4 KiB pages, which is
    /// 2^(9*4 + 12) = 2^48 = 256 TiB. The uniform 512-entry shape is a
    /// coincidence of `block_size == 9` and not something to rely on — a part
    /// with a different block size has a differently sized leaf table, which
    /// is why [`entries_at`] computes it rather than returning 512.
    pub const GMC11: Geometry = Geometry {
        max_pfn: 1 << 36,
        root_level: Level::Pdb2,
        block_size: 9,
        fragment_size: 9,
    };

    /// `amdgpu_vm_pt_level_shift` — how far to shift a PFN to get this
    /// level's index. In GPU pages, so the VA bit position is this plus 12.
    pub fn level_shift(&self, level: Level) -> u32 {
        match level {
            Level::Ptb => 0,
            _ => 9 * (Level::Pdb0 as u32 - level as u32) + self.block_size,
        }
    }

    /// `amdgpu_vm_pt_num_entries` — how many entries a table at this level
    /// has. The root is sized to cover `max_pfn` and no more; the leaf is
    /// `1 << block_size`; everything between is a fixed 512.
    pub fn entries_at(&self, level: Level) -> u64 {
        if level == self.root_level {
            let shift = self.level_shift(self.root_level);
            self.max_pfn.div_ceil(1u64 << shift)
        } else if level == Level::Ptb {
            1u64 << self.block_size
        } else {
            512
        }
    }

    /// The levels actually walked, root first.
    pub fn levels(&self) -> impl Iterator<Item = Level> + '_ {
        Level::ALL
            .into_iter()
            .filter(move |l| *l >= self.root_level)
    }

    /// This level's index for `va`.
    ///
    /// `va` must already have had the canonical hole removed (see
    /// [`strip_hole`]) — the hardware is programmed as though the hole does
    /// not exist, so an unstripped high address indexes off the end of the
    /// root table.
    pub fn index_at(&self, va: u64, level: Level) -> u64 {
        let pfn = va >> GPU_PAGE_SHIFT;
        (pfn >> self.level_shift(level)) & (self.entries_at(level) - 1)
    }

    /// `pte_fragment_size` as `DEV_INFO` reports it: bytes, not a log2.
    pub fn fragment_bytes(&self) -> u64 {
        (1u64 << self.fragment_size) * GPU_PAGE_SIZE
    }

    /// The usable address range, `[bottom, top)`.
    ///
    /// `amdgpu_gem_va_ioctl` rejects anything below `VA_RESERVED_BOTTOM` — the
    /// first 64 KiB, kept clear so a null GPU pointer faults — and anything at
    /// or above `max_pfn * PAGE - VA_RESERVED_TOP`, where the CSA, the seq64
    /// page and the trap handler live.
    pub fn usable(&self) -> (u64, u64) {
        (
            VA_RESERVED_BOTTOM,
            self.max_pfn * GPU_PAGE_SIZE - VA_RESERVED_TOP,
        )
    }
}

/// `AMDGPU_VA_RESERVED_BOTTOM` — 64 KiB, so a null GPU address faults.
pub const VA_RESERVED_BOTTOM: u64 = 1 << 16;
/// `AMDGPU_VA_RESERVED_TRAP_SIZE`.
pub const VA_RESERVED_TRAP: u64 = 1 << 16;
/// `AMDGPU_VA_RESERVED_SEQ64_SIZE`.
pub const VA_RESERVED_SEQ64: u64 = 2 << 20;
/// `AMDGPU_VA_RESERVED_CSA_SIZE`.
pub const VA_RESERVED_CSA: u64 = 2 << 20;
/// `AMDGPU_VA_RESERVED_TOP` — the trap handler, the seq64 page and the CSA.
pub const VA_RESERVED_TOP: u64 = VA_RESERVED_TRAP + VA_RESERVED_SEQ64 + VA_RESERVED_CSA;

/// `AMDGPU_GMC_HOLE_START` / `_END` / `_MASK` for a 48-bit space
/// (`max_level != 4`). The hole is the non-canonical middle of a 48-bit
/// address space, exactly as on the CPU side.
pub const GMC_HOLE_START: u64 = 0x0000_8000_0000_0000;
pub const GMC_HOLE_END: u64 = 0xffff_8000_0000_0000;
pub const GMC_HOLE_MASK: u64 = 0x0000_ffff_ffff_ffff;

/// `args->va_address &= AMDGPU_GMC_HOLE_MASK`.
///
/// "Hardware is programmed as if the hole doesn't exist", so a sign-extended
/// high address has its upper 16 bits dropped to yield the linear address the
/// page tables are indexed by.
pub const fn strip_hole(va: u64) -> u64 {
    va & GMC_HOLE_MASK
}

// ── PTE composition ────────────────────────────────────────────────────

/// Base flags for a mapping, before the per-request refinement.
///
/// `amdgpu_vm.c`: `flags = AMDGPU_PTE_VALID | AMDGPU_PTE_SNOOPED | ...` with
/// readable/writeable/executable added for a normal mapping.
pub fn base_flags(system: bool) -> u64 {
    let mut flags = PTE_VALID | PTE_SNOOPED;
    if system {
        flags |= PTE_SYSTEM;
    }
    flags
}

/// `gmc_v11_0_get_vm_pte` — turn a client's `AMDGPU_VM_PAGE_*` word into PTE
/// bits, on top of `base`.
///
/// Transcribed arm for arm, because the negative cases matter as much as the
/// positive ones: Linux CLEARS `EXECUTABLE` and `NOALLOC` when the request
/// does not ask for them rather than leaving whatever was there, and PRT
/// clears `VALID` — a PRT entry is deliberately not a valid translation.
pub fn pte_flags(base: u64, vm_flags: u32, bo_uncached: bool) -> u64 {
    let mut flags = base;

    if vm_flags & uapi::AMDGPU_VM_PAGE_READABLE != 0 {
        flags |= PTE_READABLE;
    } else {
        flags &= !PTE_READABLE;
    }
    if vm_flags & uapi::AMDGPU_VM_PAGE_WRITEABLE != 0 {
        flags |= PTE_WRITEABLE;
    } else {
        flags &= !PTE_WRITEABLE;
    }
    if vm_flags & uapi::AMDGPU_VM_PAGE_EXECUTABLE != 0 {
        flags |= PTE_EXECUTABLE;
    } else {
        flags &= !PTE_EXECUTABLE;
    }

    flags = with_mtype(
        flags,
        match vm_flags & uapi::AMDGPU_VM_MTYPE_MASK {
            uapi::AMDGPU_VM_MTYPE_WC => MTYPE_WC,
            uapi::AMDGPU_VM_MTYPE_CC => MTYPE_CC,
            uapi::AMDGPU_VM_MTYPE_UC => MTYPE_UC,
            // DEFAULT, NC, and anything else: non-coherent.
            _ => MTYPE_NC,
        },
    );

    if vm_flags & uapi::AMDGPU_VM_PAGE_NOALLOC != 0 {
        flags |= PTE_NOALLOC;
    } else {
        flags &= !PTE_NOALLOC;
    }

    if vm_flags & uapi::AMDGPU_VM_PAGE_PRT != 0 {
        flags |= PTE_PRT | PTE_SNOOPED | PTE_LOG | PTE_SYSTEM;
        flags &= !PTE_VALID;
    }

    // A buffer created COHERENT / EXT_COHERENT / UNCACHED overrides the
    // request's memory type — the BO's own property wins, and it is applied
    // last for that reason.
    if bo_uncached {
        flags = with_mtype(flags, MTYPE_UC);
    }
    flags
}

/// One leaf entry: a physical address with its flags.
///
/// The address occupies bits 47:12 of the entry, which is why it must be page
/// aligned — a misaligned address would spill into the flag bits below.
pub fn make_pte(phys: u64, flags: u64) -> Result<u64, FsError> {
    if phys & (GPU_PAGE_SIZE - 1) != 0 {
        return Err(FsError::InvalidData);
    }
    if phys & !GMC_HOLE_MASK != 0 {
        return Err(FsError::InvalidData);
    }
    Ok(phys | flags)
}

// ── AMDGPU_GEM_VA ──────────────────────────────────────────────────────

/// One recorded mapping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub va: u64,
    pub size: u64,
    pub gem_handle: u32,
    pub offset: u64,
    pub vm_flags: u32,
}

/// Per-open GPU address space.
///
/// Keyed by start address so an overlap check is two neighbour lookups rather
/// than a scan. Linux keeps the same thing in an interval tree per
/// `amdgpu_vm`, one per DRM file.
#[derive(Debug)]
pub struct VmState {
    geometry: Geometry,
    mappings: IrqSafeSpinLock<Option<BTreeMap<u64, Mapping>>>,
}

impl Default for VmState {
    fn default() -> Self {
        Self::new()
    }
}

impl VmState {
    pub const fn new() -> Self {
        VmState {
            geometry: Geometry::GMC11,
            mappings: IrqSafeSpinLock::new(None),
        }
    }

    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Whatever mapping covers `va`, if any.
    pub fn lookup(&self, va: u64) -> Option<Mapping> {
        let g = self.mappings.lock();
        let map = g.as_ref()?;
        map.range(..=va)
            .next_back()
            .map(|(_, m)| *m)
            .filter(|m| va < m.va.saturating_add(m.size))
    }

    fn overlaps(map: &BTreeMap<u64, Mapping>, va: u64, size: u64) -> bool {
        let end = va.saturating_add(size);
        // The mapping starting at or before `va`, and the one after it.
        if let Some((_, prev)) = map.range(..=va).next_back() {
            if va < prev.va.saturating_add(prev.size) {
                return true;
            }
        }
        if let Some((next_va, _)) = map.range(va..).next() {
            if *next_va < end {
                return true;
            }
        }
        false
    }

    fn insert(&self, mapping: Mapping, replace: bool) -> Result<(), FsError> {
        let mut g = self.mappings.lock();
        let map = g.get_or_insert_with(BTreeMap::new);
        if replace {
            Self::clear_range(map, mapping.va, mapping.size);
        } else if Self::overlaps(map, mapping.va, mapping.size) {
            // `amdgpu_vm_bo_map` returns -EINVAL for an overlap; REPLACE is
            // the op that asks for one to be dropped.
            return Err(FsError::InvalidData);
        }
        map.insert(mapping.va, mapping);
        Ok(())
    }

    /// Drop every mapping intersecting `[va, va+size)`.
    fn clear_range(map: &mut BTreeMap<u64, Mapping>, va: u64, size: u64) {
        let end = va.saturating_add(size);
        let doomed: Vec<u64> = map
            .iter()
            .filter(|(_, m)| m.va < end && va < m.va.saturating_add(m.size))
            .map(|(k, _)| *k)
            .collect();
        for k in doomed {
            map.remove(&k);
        }
    }

    fn unmap(&self, va: u64, size: u64) -> Result<(), FsError> {
        let mut g = self.mappings.lock();
        let map = g.get_or_insert_with(BTreeMap::new);
        // UNMAP names an existing mapping exactly; Linux answers -ENOENT when
        // no mapping starts there.
        match map.get(&va) {
            Some(m) if m.size == size => {
                map.remove(&va);
                Ok(())
            }
            Some(_) => Err(FsError::InvalidData),
            None => Err(FsError::NotFound),
        }
    }

    fn clear(&self, va: u64, size: u64) -> Result<(), FsError> {
        let mut g = self.mappings.lock();
        let map = g.get_or_insert_with(BTreeMap::new);
        Self::clear_range(map, va, size);
        Ok(())
    }

    /// How many mappings this address space holds.
    ///
    /// Ungated: the kernel-test modules compile in the plain build too, so a
    /// `cfg(feature = "kernel-test")` gate would leave them unable to see it.
    /// Named for what it counts rather than `len`, which would invite the
    /// `len_without_is_empty` lint for an accessor nothing iterates.
    pub fn mapping_count(&self) -> usize {
        self.mappings.lock().as_ref().map_or(0, |m| m.len())
    }
}

/// `amdgpu_gem_va_ioctl`'s validation, in its order.
///
/// The order is ABI: a request that is wrong in two ways gets the errno of the
/// first check, and a client bisecting its own bug sees that one.
pub fn validate_va(
    geometry: &Geometry,
    va_raw: u64,
    size: u64,
    flags: u32,
) -> Result<u64, FsError> {
    if va_raw < VA_RESERVED_BOTTOM {
        return Err(FsError::InvalidData);
    }
    // Linux writes this as two comparisons; the range is the same test.
    if (GMC_HOLE_START..GMC_HOLE_END).contains(&va_raw) {
        return Err(FsError::InvalidData);
    }
    let va = strip_hole(va_raw);

    let (_, top) = geometry.usable();
    let end = va.checked_add(size).ok_or(FsError::InvalidData)?;
    if end > top {
        return Err(FsError::InvalidData);
    }

    // `valid_flags` and `prt_flags` are alternatives, not a union: a request
    // must satisfy one of them wholly. PRT is its own mode and cannot be
    // combined with the ordinary page permissions.
    const VALID_FLAGS: u32 = uapi::AMDGPU_VM_DELAY_UPDATE
        | uapi::AMDGPU_VM_PAGE_READABLE
        | uapi::AMDGPU_VM_PAGE_WRITEABLE
        | uapi::AMDGPU_VM_PAGE_EXECUTABLE
        | uapi::AMDGPU_VM_MTYPE_MASK
        | uapi::AMDGPU_VM_PAGE_NOALLOC;
    const PRT_FLAGS: u32 = uapi::AMDGPU_VM_DELAY_UPDATE | uapi::AMDGPU_VM_PAGE_PRT;
    if flags & !VALID_FLAGS != 0 && flags & !PRT_FLAGS != 0 {
        return Err(FsError::InvalidData);
    }
    Ok(va)
}

/// `DRM_IOCTL_AMDGPU_GEM_VA` for one open.
pub fn dispatch(
    cmd: u32,
    arg: usize,
    vm: &VmState,
    gem: &crate::amdgpu_gem::GemState,
) -> Result<u64, FsError> {
    if drm_uapi::ioc_nr(cmd) != drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_VA {
        return Err(FsError::Unsupported);
    }
    // `struct drm_amdgpu_gem_va`: handle u32, _pad u32, operation u32,
    // flags u32, va_address u64, offset_in_bo u64, map_size u64.
    // SAFETY: `arg` is the ioctl pointer the trap layer validated (or
    // kernel-owned on the test path); `copy_in` bounds-checks and brackets it.
    let bytes = unsafe { copy_in(arg, 40)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let operation = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let va_raw = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let offset = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let size = u64::from_le_bytes(bytes[32..40].try_into().unwrap());

    let va = validate_va(&vm.geometry, va_raw, size, flags)?;

    // The operation is checked after the address, as Linux checks it.
    match operation {
        uapi::AMDGPU_VA_OP_MAP
        | uapi::AMDGPU_VA_OP_UNMAP
        | uapi::AMDGPU_VA_OP_CLEAR
        | uapi::AMDGPU_VA_OP_REPLACE => {}
        _ => return Err(FsError::InvalidData),
    }

    // PRT has no backing object and no page-table write to make; refuse it
    // rather than record a mapping nothing can honour.
    if flags & uapi::AMDGPU_VM_PAGE_PRT != 0 {
        return Err(FsError::Unsupported);
    }

    match operation {
        uapi::AMDGPU_VA_OP_MAP | uapi::AMDGPU_VA_OP_REPLACE => {
            // A mapping must name a live buffer in THIS open's table, and must
            // fit inside it: `offset + size` past the end would map pages the
            // buffer does not own.
            let object = gem.object(handle).ok_or(FsError::InvalidData)?;
            let span = offset.checked_add(size).ok_or(FsError::InvalidData)?;
            if span > object.byte_len {
                return Err(FsError::InvalidData);
            }
            if size == 0
                || va & (GPU_PAGE_SIZE - 1) != 0
                || size & (GPU_PAGE_SIZE - 1) != 0
                || offset & (GPU_PAGE_SIZE - 1) != 0
            {
                return Err(FsError::InvalidData);
            }
            vm.insert(
                Mapping {
                    va,
                    size,
                    gem_handle: handle,
                    offset,
                    vm_flags: flags,
                },
                operation == uapi::AMDGPU_VA_OP_REPLACE,
            )?;
        }
        uapi::AMDGPU_VA_OP_UNMAP => vm.unmap(va, size)?,
        uapi::AMDGPU_VA_OP_CLEAR => vm.clear(va, size)?,
        _ => unreachable!("operation validated above"),
    }
    Ok(0)
}
