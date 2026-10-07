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
    /// The root page directory and the hierarchy beneath it. `None` until the
    /// first mapping, so an open that never submits allocates nothing.
    root: IrqSafeSpinLock<Option<Node>>,
    /// Tables allocated, bounded by [`MAX_TABLES`].
    tables: IrqSafeSpinLock<u64>,
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
            root: IrqSafeSpinLock::new(None),
            tables: IrqSafeSpinLock::new(0),
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
            let replace = operation == uapi::AMDGPU_VA_OP_REPLACE;
            if replace {
                // REPLACE drops whatever it covers, so the old translations
                // must go before the new ones are written — otherwise a page
                // the old mapping owned stays reachable under the new one.
                vm.dematerialise(va, size);
            }
            let mapping = Mapping {
                va,
                size,
                gem_handle: handle,
                offset,
                vm_flags: flags,
            };
            vm.insert(mapping, replace)?;
            // A buffer created COHERENT / EXT_COHERENT / UNCACHED forces the
            // memory type, whatever the mapping asked for.
            let uncached = object.flags
                & (uapi::AMDGPU_GEM_CREATE_COHERENT
                    | uapi::AMDGPU_GEM_CREATE_EXT_COHERENT
                    | uapi::AMDGPU_GEM_CREATE_UNCACHED) as u64
                != 0;
            if let Err(error) = vm.materialise(&mapping, object.phys, uncached) {
                // Leave neither half-written tables nor a mapping record
                // claiming translations that do not exist.
                vm.dematerialise(va, size);
                let _ = vm.unmap(va, size);
                return Err(error);
            }
        }
        uapi::AMDGPU_VA_OP_UNMAP => {
            vm.unmap(va, size)?;
            vm.dematerialise(va, size);
        }
        uapi::AMDGPU_VA_OP_CLEAR => {
            vm.clear(va, size)?;
            vm.dematerialise(va, size);
        }
        _ => unreachable!("operation validated above"),
    }
    Ok(0)
}

// ── Page-table materialisation ──────────────────────────────────────────

/// One allocated page table: `entries_at(level)` 64-bit entries.
///
/// Every level's table is one GPU page here. That is exact for GMC 11, where
/// each level holds 512 entries of 8 bytes; a part whose `block_size` made a
/// level larger would need a higher-order allocation, which [`PageTable::new`]
/// computes rather than assumes.
#[derive(Debug)]
struct PageTable {
    phys: u64,
    order: u8,
}

impl PageTable {
    /// Allocate and clear a table for `level`.
    ///
    /// A fresh table is filled with the INVALID pattern, not with zeros.
    /// `amdgpu_vm_pt_clear` writes `AMDGPU_PTE_EXECUTABLE` into a leaf's
    /// entries on everything from Vega 10 on — a fault-priority workaround —
    /// and `AMDGPU_PDE_PTE` into a directory's. Neither carries `PTE_VALID`,
    /// so neither translates; the difference is which fault the hardware
    /// reports, and reporting the wrong one sends a future debugging session
    /// in the wrong direction.
    fn new(geometry: &Geometry, level: Level) -> Result<Self, FsError> {
        let bytes = geometry.entries_at(level) * 8;
        let pages = bytes.div_ceil(GPU_PAGE_SIZE);
        let mut order = 0u8;
        while (1u64 << order) < pages {
            order += 1;
        }
        let frame = narf_memory::frame::alloc_pages_on(0, order).map_err(|_| FsError::NoSpace)?;
        let table = PageTable {
            phys: frame.start_address().raw(),
            order,
        };
        let invalid: u64 = if level == Level::Ptb {
            PTE_EXECUTABLE
        } else {
            PDE_PTE
        };
        for i in 0..geometry.entries_at(level) {
            // SAFETY: `i` is bounded by the table's entry count and the
            // allocation covers that many 8-byte entries.
            unsafe { table.write(i, invalid) };
        }
        Ok(table)
    }

    /// Write entry `index`.
    ///
    /// # Safety
    /// `index` must be within the table's entry count.
    unsafe fn write(&self, index: u64, value: u64) {
        // SAFETY: physical memory is kernel-mapped at a fixed offset, and the
        // caller bounds `index` against the allocation.
        unsafe {
            let base = narf_memory::PhysAddr::new(self.phys).kernel_mut_ptr::<u64>();
            base.add(index as usize).write_volatile(value);
        }
    }

    /// Read entry `index`.
    ///
    /// # Safety
    /// As [`PageTable::write`].
    unsafe fn read(&self, index: u64) -> u64 {
        // SAFETY: as above.
        unsafe {
            let base = narf_memory::PhysAddr::new(self.phys).kernel_ptr::<u64>();
            base.add(index as usize).read_volatile()
        }
    }
}

impl Drop for PageTable {
    fn drop(&mut self) {
        let frame = narf_memory::PhysFrame::containing(narf_memory::PhysAddr::new(self.phys));
        narf_memory::frame::free_pages(frame, self.order);
    }
}

/// A directory and the children it points at, keyed by entry index.
#[derive(Debug)]
struct Node {
    table: PageTable,
    children: BTreeMap<u64, Node>,
    /// Live leaf entries beneath this node, so an emptied subtree can be freed
    /// without walking it.
    live: u64,
}

/// `amdgpu_gmc_get_pde_for_bo` + `gmc_v11_0_get_vm_pde`, for a table in system
/// memory — which every table here is.
///
/// `amdgpu_ttm_tt_pde_flags` gives `VALID | SYSTEM | SNOOPED` for a cached
/// TT placement, and `gmc_v11_0_get_vm_pde` then skips the VRAM MC→PA
/// conversion precisely because `SYSTEM` is set. `AMDGPU_PDE_PTE` is NOT set:
/// that marks a directory entry as a leaf mapping a huge page, and this one
/// points at a child table.
fn make_pde(table_phys: u64) -> Result<u64, FsError> {
    // `BUG_ON(*addr & 0xFFFF00000000003FULL)` — the address field is bits
    // 47:6, so a PDE address must be 64-byte aligned and inside 48 bits.
    if table_phys & 0xFFFF_0000_0000_003F != 0 {
        return Err(FsError::InvalidData);
    }
    Ok(table_phys | PTE_VALID | PTE_SYSTEM | PTE_SNOOPED)
}

/// A bound on the tables one address space may hold.
///
/// GMC 11 can address 256 TiB, and a client that mapped all of it would ask
/// for 2^27 leaf tables — half a terabyte of page tables. Linux survives that
/// because TTM evicts page tables under pressure; nothing here does, so the
/// allocation is capped and a map beyond it is ENOMEM. 4096 tables is 16 MiB
/// of tables, enough for 8 GiB of mappings at 4 KiB granularity.
const MAX_TABLES: u64 = 4096;

impl VmState {
    /// Physical address of the root page directory, for
    /// `VM_CONTEXTn_PAGE_TABLE_BASE_ADDR`. `None` until something is mapped.
    pub fn root_phys(&self) -> Option<u64> {
        self.root.lock().as_ref().map(|n| n.table.phys)
    }

    /// Tables currently allocated, root included.
    pub fn table_count(&self) -> u64 {
        *self.tables.lock()
    }

    /// Write the leaf entries for `mapping`, creating directories as needed.
    ///
    /// LINUX-GAP: one PTE per 4 KiB page, always. Linux coalesces a run into a
    /// huge leaf PDE when the alignment allows (`AMDGPU_PTE_FRAG` and
    /// `AMDGPU_PDE_PTE`), which is both faster to write and cheaper for the
    /// hardware to walk. Doing that needs the fragment logic in
    /// `amdgpu_vm_pt_update_range`, and getting it wrong maps more than was
    /// asked for — so the slow, exact form comes first.
    fn materialise(
        &self,
        mapping: &Mapping,
        phys_base: u64,
        uncached: bool,
    ) -> Result<(), FsError> {
        let geometry = self.geometry;
        let flags = pte_flags(base_flags(true), mapping.vm_flags, uncached);
        let pages = mapping.size / GPU_PAGE_SIZE;

        let mut root_guard = self.root.lock();
        let mut tables = self.tables.lock();
        if root_guard.is_none() {
            *root_guard = Some(Node {
                table: PageTable::new(&geometry, geometry.root_level)?,
                children: BTreeMap::new(),
                live: 0,
            });
            *tables += 1;
        }

        for page in 0..pages {
            let va = mapping.va + page * GPU_PAGE_SIZE;
            let phys = phys_base + mapping.offset + page * GPU_PAGE_SIZE;
            let pte = make_pte(phys, flags)?;

            // Descend, creating each missing directory and linking it into its
            // parent as we go.
            let mut node = root_guard.as_mut().expect("root just ensured");
            let levels: Vec<Level> = geometry.levels().collect();
            for window in levels.windows(2) {
                let (level, child_level) = (window[0], window[1]);
                let index = geometry.index_at(va, level);
                if !node.children.contains_key(&index) {
                    if *tables >= MAX_TABLES {
                        return Err(FsError::NoSpace);
                    }
                    let child = PageTable::new(&geometry, child_level)?;
                    let pde = make_pde(child.phys)?;
                    // SAFETY: `index` is masked to the level's entry count by
                    // `index_at`.
                    unsafe { node.table.write(index, pde) };
                    *tables += 1;
                    node.children.insert(
                        index,
                        Node {
                            table: child,
                            children: BTreeMap::new(),
                            live: 0,
                        },
                    );
                }
                node.live += 1;
                node = node.children.get_mut(&index).expect("just inserted");
            }

            let leaf = geometry.index_at(va, Level::Ptb);
            // SAFETY: as above.
            unsafe { node.table.write(leaf, pte) };
            node.live += 1;
        }
        Ok(())
    }

    /// Restore the invalid pattern over `[va, va+size)` and free directories
    /// that no longer hold anything.
    fn dematerialise(&self, va: u64, size: u64) {
        let geometry = self.geometry;
        let pages = size / GPU_PAGE_SIZE;
        let mut root_guard = self.root.lock();
        let mut tables = self.tables.lock();
        let Some(root) = root_guard.as_mut() else {
            return;
        };
        let levels: Vec<Level> = geometry.levels().collect();

        for page in 0..pages {
            let va = va + page * GPU_PAGE_SIZE;
            Self::clear_one(&geometry, root, &levels, 0, va, &mut tables);
        }
        if root.live == 0 {
            *tables -= 1;
            *root_guard = None;
        }
    }

    /// Clear one leaf and unwind, freeing any directory left empty. Recursive
    /// so the unwind happens on the way back up, which is the only point at
    /// which a parent knows whether its child became empty.
    fn clear_one(
        geometry: &Geometry,
        node: &mut Node,
        levels: &[Level],
        depth: usize,
        va: u64,
        tables: &mut u64,
    ) {
        let level = levels[depth];
        let index = geometry.index_at(va, level);
        if level == Level::Ptb {
            // SAFETY: `index` is masked to the table's entry count.
            let current = unsafe { node.table.read(index) };
            if current & PTE_VALID == 0 {
                return;
            }
            // SAFETY: as above.
            unsafe { node.table.write(index, PTE_EXECUTABLE) };
            node.live = node.live.saturating_sub(1);
            return;
        }
        let Some(child) = node.children.get_mut(&index) else {
            return;
        };
        let before = child.live;
        Self::clear_one(geometry, child, levels, depth + 1, va, tables);
        if child.live == before {
            // Nothing changed below, so nothing to unwind.
            return;
        }
        node.live = node.live.saturating_sub(1);
        if child.live == 0 {
            // SAFETY: `index` is masked to the table's entry count.
            unsafe { node.table.write(index, PDE_PTE) };
            node.children.remove(&index);
            *tables -= 1;
        }
    }

    /// Read a leaf entry for `va`, for tests and for a future fault handler.
    pub fn leaf_entry(&self, va: u64) -> Option<u64> {
        let geometry = self.geometry;
        let g = self.root.lock();
        let mut node = g.as_ref()?;
        let levels: Vec<Level> = geometry.levels().collect();
        for window in levels.windows(2) {
            let index = geometry.index_at(va, window[0]);
            node = node.children.get(&index)?;
        }
        // SAFETY: `index_at` masks to the table's entry count.
        Some(unsafe { node.table.read(geometry.index_at(va, Level::Ptb)) })
    }

    /// Read a directory entry at `level` for `va`.
    pub fn directory_entry(&self, va: u64, level: Level) -> Option<u64> {
        let geometry = self.geometry;
        let g = self.root.lock();
        let mut node = g.as_ref()?;
        for window in geometry.levels().collect::<Vec<_>>().windows(2) {
            if window[0] == level {
                // SAFETY: as above.
                return Some(unsafe { node.table.read(geometry.index_at(va, level)) });
            }
            node = node.children.get(&geometry.index_at(va, window[0]))?;
        }
        None
    }
}

// ── Activating an address space on the hardware ─────────────────────────

/// Why an address space could not be made live.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ActivateError {
    /// Nothing is mapped, so there is no root page directory to point at.
    NoPageTables,
    /// Every user VMID is bound and none could be evicted.
    Vmid(crate::amdgpu_vmid::VmidError),
    /// The TLB invalidate did not acknowledge within its budget.
    Tlb(crate::amdgpu_vmhub_regs::TlbInvalidateError),
}

impl Geometry {
    /// `vm_manager.num_level` — directory levels ABOVE the leaf, which is what
    /// `PAGE_TABLE_DEPTH` holds. 3 on GMC 11, where four levels are walked.
    ///
    /// Writing 4 here would make the MMU expect a fifth level that does not
    /// exist and treat the root's entries as pointers to tables that are
    /// really leaves.
    pub fn num_level(&self) -> u8 {
        (Level::Ptb as u8) - (self.root_level as u8)
    }
}

/// Make `vm`'s page tables the ones the GPU walks for a VMID.
///
/// The sequence is `gfxhub_v3_0_setup_vmid_config` plus
/// `gmc_v11_0_flush_gpu_tlb`, in that order, and the order is not negotiable:
/// the page-table base and the address bounds must be in place before the
/// context is enabled, and the TLB must be invalidated after, or the MMU
/// serves translations cached for whatever previously held this VMID. That
/// last point is the whole reason this is one function rather than three calls
/// a caller sequences itself — a forgotten invalidate is one process reading
/// another's memory, and it does not fail loudly.
///
/// Both hubs are programmed. The GFX hub serves the shader engines and the MM
/// hub serves the display and multimedia blocks; a VMID bound in one and not
/// the other translates for some engines and faults for others.
///
/// LINUX-GAP: `fault_on_invalid` is always true here — RETRY is never set. A
/// compute client that prefetches past a buffer wants the retry behaviour, and
/// choosing it needs the per-context flag `AMDGPU_VM_PAGE_PRT` and friends
/// carry; until a submission can express it, faulting is the safer default.
#[allow(clippy::too_many_arguments)]
pub fn activate<MG, MM>(
    vm: &VmState,
    pool: &mut crate::amdgpu_vmid::VmidPool,
    pasid: crate::amdgpu_vmid::Pasid,
    mmio_gfx: &mut MG,
    regs_gfx: &crate::amdgpu_vmhub_regs::VmHubRegs,
    mmio_mm: &mut MM,
    regs_mm: &crate::amdgpu_vmhub_regs::VmHubRegs,
) -> Result<u8, ActivateError>
where
    MG: crate::amdgpu_vmhub_regs::VmHubMmio,
    MM: crate::amdgpu_vmhub_regs::VmHubMmio,
{
    use crate::amdgpu_vmhub_regs as hub;

    // An address space with nothing mapped has no root directory. Binding a
    // VMID to address 0 would point the MMU at physical page 0.
    let root = vm.root_phys().ok_or(ActivateError::NoPageTables)?;
    let geometry = vm.geometry();
    let vmid = pool.bind(pasid, root).map_err(ActivateError::Vmid)?;

    let depth = geometry.num_level();
    let block_size = geometry.block_size as u8;
    let end_pfn = geometry.max_pfn - 1;

    // Written out twice rather than looped over a trait object: `VmHubMmio`'s
    // helpers are generic, and the two hubs have different concrete MMIO types
    // because they are different register windows.
    fn program_hub<M: hub::VmHubMmio>(
        mmio: &mut M,
        regs: &hub::VmHubRegs,
        vmid: u8,
        root: u64,
        end_pfn: u64,
        depth: u8,
        block_size: u8,
    ) {
        hub::write_vmid_pt_base(mmio, regs, vmid, root);
        hub::write_vmid_aperture(mmio, regs, vmid, 0, end_pfn);
        hub::write_vmid_cntl(mmio, regs, vmid, depth, block_size, true);
    }
    program_hub(mmio_gfx, regs_gfx, vmid, root, end_pfn, depth, block_size);
    program_hub(mmio_mm, regs_mm, vmid, root, end_pfn, depth, block_size);

    hub::invalidate_vmid_full(mmio_gfx, regs_gfx, mmio_mm, regs_mm, vmid)
        .map_err(ActivateError::Tlb)?;
    Ok(vmid)
}
