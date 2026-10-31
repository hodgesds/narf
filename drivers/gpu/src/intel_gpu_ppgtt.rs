//! PPGTT walker — per-process / per-context page tables for
//! Gen12 (issue #1012).
//!
//! Reference: **Tiger Lake PRM Vol. 5 §"Memory Views"** — the
//! PPGTT is a 4-level radix walk over 48-bit GPU virtual
//! addresses, sharing the 64-bit GFX PTE layout defined in
//! [`crate::intel_gpu_gtt`]:
//!
//! ```text
//!   VA bits 47:39  PML4 index    (512 entries)
//!   VA bits 38:30  PDPT index    (512 entries)
//!   VA bits 29:21  PD index      (512 entries)
//!   VA bits 20:12  PT index      (512 entries)
//!   VA bits 11:0   page offset
//! ```
//!
//! Every table is one 4 KiB page of 512 8-byte entries. An
//! intermediate entry is `PRESENT | RW | PAT[1:0] | phys` of the next-level
//! table ([`crate::intel_gpu_gtt::encode_table_entry`]); a leaf
//! entry is an engine PTE
//! ([`crate::intel_gpu_gtt::encode_engine_pte`]). The execlists
//! context of a process programs the PML4 root through its PDP
//! register pairs — that half lives in
//! [`crate::intel_gpu_rcs::RcsEngine::attach_ppgtt`].
//!
//! ## Ownership
//!
//! A [`Ppgtt`] owns every table page it allocates: intermediate
//! tables are created on first use, freed again when an unmap
//! leaves them empty, and [`Ppgtt::teardown`] returns the whole
//! tree. Leaf pages are the *caller's* frames — the walker maps
//! and unmaps them but never frees them. Table pages come from
//! a [`PtMemory`] seam: production allocates host frames (the
//! walker runs on physical addresses, exactly as the hardware
//! walk does), fixtures allocate from a modelled physical
//! memory so the full conversation runs without silicon.
//!
//! ## Tamper discipline
//!
//! The walker validates every entry it follows: a present entry
//! whose bits fall outside the level's documented encoding
//! (reserved bits set, or a zero physical address) is a
//! [`WalkOutcome::Corrupt`] at that level, never silently
//! followed. A driver that programs these tables itself should
//! only ever produce well-formed entries, so a corrupt entry
//! means the table was written by someone else — firmware, a
//! peer engine, a bug — and the honest answer is to say so.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::intel_gpu_gtt::{
    encode_table_entry_with_pat, pte_phys, pte_present, GttError, PatSlot, PteFormat,
    GTT_PAGE_SIZE, PTE_PAT0, PTE_PAT1, PTE_PAT2, PTE_PAT3, PTE_PHYS_MASK, PTE_PRESENT, PTE_RW,
};

/// Virtual-address width of the Gen12 PPGTT (PRM Vol. 5).
pub const PPGTT_VA_BITS: u32 = 48;
/// Total PPGTT virtual space: 256 TiB.
pub const PPGTT_VA_SIZE: u64 = 1 << PPGTT_VA_BITS;
/// Entries per table page, every level.
pub const ENTRIES_PER_TABLE: usize = 512;
/// Number of walk levels: PML4, PDPT, PD, PT.
pub const LEVELS: usize = 4;
/// Index shift of each level, root first.
pub const LEVEL_SHIFTS: [u32; LEVELS] = [39, 30, 21, 12];
/// Level numbers used in [`WalkOutcome`]: 0 = PML4, 1 = PDPT,
/// 2 = PD, 3 = PT (the leaf level).
pub const LEVEL_PML4: u8 = 0;
/// PDPT level number (see [`LEVEL_PML4`]).
pub const LEVEL_PDPT: u8 = 1;
/// PD level number (see [`LEVEL_PML4`]).
pub const LEVEL_PD: u8 = 2;
/// PT (leaf) level number (see [`LEVEL_PML4`]).
pub const LEVEL_PT: u8 = 3;

/// Non-leaf entries have PRESENT, RW, two PAT bits and a physical address.
const TABLE_ENTRY_ALLOWED: u64 = PTE_PRESENT | PTE_RW | PTE_PHYS_MASK | PTE_PAT0 | PTE_PAT1;
const PTE_NULL: u64 = 1 << 9; // MIT xe_gtt_defs.h: reads zero, writes discarded.
pub(crate) const PTE_DM: u64 = 1 << 11; // XE_PPGTT_PTE_DM: device (local) memory.
/// Bits a well-formed *leaf* entry may carry: every flag the
/// GFX PTE definition assigns, plus the physical address.
const LEAF_ENTRY_ALLOWED: u64 =
    PTE_PRESENT | PTE_RW | PTE_PHYS_MASK | PTE_PAT0 | PTE_PAT1 | PTE_PAT2;

/// Failure modes of the PPGTT walker.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PpgttError {
    /// Virtual address at or beyond the 48-bit PPGTT space.
    VaOutOfRange,
    /// Virtual or physical address not 4 KiB aligned.
    Unaligned,
    /// Physical address outside the documented 46-bit space.
    PhysOutOfRange,
    /// The leaf slot already maps a page.
    AlreadyMapped,
    /// [`Ppgtt::unmap`] named a VA with no leaf mapping.
    NotMapped,
    /// Table-page allocation failed.
    OutOfMemory,
    /// PAT index is unavailable for this page-table format.
    InvalidPatIndex,
    /// An intermediate entry on the map path is present but not
    /// well-formed (see [`WalkOutcome::Corrupt`]); the walker
    /// will not overwrite foreign state silently. `level` is
    /// the level whose entry failed validation.
    CorruptEntry {
        /// Level whose entry failed validation.
        level: u8,
    },
}

impl From<GttError> for PpgttError {
    fn from(e: GttError) -> Self {
        match e {
            GttError::UnalignedPhys => PpgttError::Unaligned,
            GttError::PhysOutOfRange => PpgttError::PhysOutOfRange,
            GttError::OutOfMemory => PpgttError::OutOfMemory,
            GttError::OutOfBounds => PpgttError::VaOutOfRange,
            GttError::InvalidPatIndex => PpgttError::InvalidPatIndex,
        }
    }
}

/// Result of walking one virtual address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WalkOutcome {
    /// Hardware NULL mapping: reads return zero and writes are discarded.
    Null,
    /// Fully walked: the physical address, page base plus the
    /// VA's in-page offset.
    Mapped(u64),
    /// The walk stopped at `level`: that level's entry is not
    /// present, so nothing below it is mapped.
    NotMapped {
        /// Level whose entry was absent (0 = PML4 .. 3 = PT).
        level: u8,
    },
    /// The walk stopped at `level`: the entry is present but is
    /// not a well-formed encoding for that level (reserved bits
    /// set, or a zero physical address). The walker refuses to
    /// follow it.
    Corrupt {
        /// Level whose entry failed validation.
        level: u8,
    },
}

/// Decompose a 48-bit VA into its four table indices, root
/// first. The caller validates the range; this is pure bit math.
pub fn va_indices(va: u64) -> [usize; LEVELS] {
    let mut idx = [0usize; LEVELS];
    for (i, shift) in LEVEL_SHIFTS.iter().enumerate() {
        idx[i] = ((va >> shift) & 0x1FF) as usize;
    }
    idx
}

/// Physical memory the walker runs over. Table pages are
/// allocated and freed through this seam and entries are read
/// and written by physical address — the same view the hardware
/// walker has. The accounting counter exists so fixtures (and
/// teardown) can assert exact balance.
pub trait PtMemory {
    /// Allocate one zeroed 4 KiB page for a page table; returns
    /// its physical address.
    fn alloc_table(&mut self) -> Result<u64, PpgttError>;
    /// Release a table page previously returned by
    /// [`Self::alloc_table`].
    fn free_table(&mut self, phys: u64);
    /// Read entry `index` of the table page at `table_phys`.
    fn read_entry(&self, table_phys: u64, index: usize) -> u64;
    /// Write entry `index` of the table page at `table_phys`.
    fn write_entry(&mut self, table_phys: u64, index: usize, val: u64);
    /// Table pages currently allocated through this seam.
    fn live_tables(&self) -> u32;
}

/// Production [`PtMemory`]: table pages are host frames. The
/// CPU reaches them through the kernel direct map; the GPU
/// walker reaches them by the physical addresses programmed
/// into the context PDPs. Ownership is exact — every allocated
/// frame is in the map until freed.
pub struct FramePtMemory {
    frames: BTreeMap<u64, narf_memory::frame::PhysFrame>,
}

impl core::fmt::Debug for FramePtMemory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FramePtMemory")
            .field("live_tables", &self.frames.len())
            .finish()
    }
}

impl FramePtMemory {
    /// An empty table-page allocator.
    pub fn new() -> Self {
        Self {
            frames: BTreeMap::new(),
        }
    }

    pub(crate) fn publish_for_device(&self) -> bool {
        crate::intel_gpu_gtt::publish_system_pages(self.frames.values())
    }

    /// Raw pointer to entry `index` of the table at `phys`.
    ///
    /// # Safety
    /// `phys` must name a frame this allocator owns and `index`
    /// must be inside the table (< 512); entries are 8 bytes, so
    /// the pointer lands inside that frame's direct-map page.
    unsafe fn entry_ptr(&self, phys: u64, index: usize) -> *mut u64 {
        debug_assert!(index < ENTRIES_PER_TABLE);
        let frame = self
            .frames
            .get(&phys)
            .expect("table page owned by allocator");
        let base = frame.start_address().kernel_mut_ptr::<u8>();
        // SAFETY: caller contract above.
        unsafe { base.add(index * 8) as *mut u64 }
    }
}

impl Default for FramePtMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl PtMemory for FramePtMemory {
    fn alloc_table(&mut self) -> Result<u64, PpgttError> {
        let frame = narf_memory::frame::alloc_frame().map_err(|_| PpgttError::OutOfMemory)?;
        let phys = frame.start_address().raw();
        self.frames.insert(phys, frame);
        for i in 0..ENTRIES_PER_TABLE {
            self.write_entry(phys, i, 0);
        }
        Ok(phys)
    }

    fn free_table(&mut self, phys: u64) {
        if let Some(frame) = self.frames.remove(&phys) {
            narf_memory::frame::free_frame(frame);
        }
    }

    fn read_entry(&self, table_phys: u64, index: usize) -> u64 {
        // SAFETY: walker only reads tables this allocator handed
        // out, at in-table indices. Volatile because the GPU
        // walker shares this memory with the CPU.
        unsafe { core::ptr::read_volatile(self.entry_ptr(table_phys, index) as *const u64) }
    }

    fn write_entry(&mut self, table_phys: u64, index: usize, val: u64) {
        // SAFETY: same contract as `read_entry`.
        unsafe { core::ptr::write_volatile(self.entry_ptr(table_phys, index), val) }
    }

    fn live_tables(&self) -> u32 {
        self.frames.len() as u32
    }
}

/// One per-process / per-context PPGTT: a PML4 root plus the
/// intermediate tables created under it. Owns its tables (see
/// module docs); leaf frames belong to the caller.
#[derive(Debug)]
pub struct Ppgtt {
    format: PteFormat,
    table_pat: u8,
    root: u64,
    tables: u32,
    mapped: u64,
    scratch: [u64; 3],
    null_pat: u8,
    nulls: BTreeSet<u64>,
}

impl Ppgtt {
    /// Create an empty PPGTT: allocate and zero the PML4 root.
    pub fn new<M: PtMemory>(mem: &mut M) -> Result<Self, PpgttError> {
        Self::with_format(mem, PteFormat::Gen12)
    }

    /// A walker for Xe-LP or Xe-LPG PPGTT leaf encodings.
    pub fn with_format<M: PtMemory>(mem: &mut M, format: PteFormat) -> Result<Self, PpgttError> {
        Self::with_table_pat(mem, format, 0)
    }

    /// Select the independently programmed cache policy for every non-leaf
    /// page and the context root descriptor. Leaves retain their own PAT.
    pub fn with_table_pat<M: PtMemory>(
        mem: &mut M,
        format: PteFormat,
        table_pat: u8,
    ) -> Result<Self, PpgttError> {
        if table_pat > 3 {
            return Err(PpgttError::InvalidPatIndex);
        }
        let root = mem.alloc_table()?;
        if let Err(error) = encode_table_entry_with_pat(root, table_pat) {
            mem.free_table(root);
            return Err(error.into());
        }
        Ok(Self {
            format,
            table_pat,
            root,
            tables: 1,
            mapped: 0,
            scratch: [0; 3],
            null_pat: 0,
            nulls: BTreeSet::new(),
        })
    }

    /// A bounded shared scratch tree covers the entire 48-bit VA space.
    /// Mapping a real page copies only its path, never modifies shared tables.
    pub fn with_scratch<M: PtMemory>(
        mem: &mut M,
        format: PteFormat,
        table_pat: u8,
        leaf_pat: u8,
    ) -> Result<Self, PpgttError> {
        format.encode_ppgtt(0, leaf_pat, true)?;
        let mut result = Self::with_table_pat(mem, format, table_pat)?;
        result.null_pat = leaf_pat;
        for level in (1..4).rev() {
            let table = match mem.alloc_table() {
                Ok(table) => table,
                Err(error) => {
                    result.teardown(mem);
                    return Err(error);
                }
            };
            if let Err(error) = encode_table_entry_with_pat(table, table_pat) {
                mem.free_table(table);
                result.teardown(mem);
                return Err(error.into());
            }
            let empty = if level == LEVEL_PT {
                format
                    .encode_ppgtt(0, leaf_pat, true)
                    .expect("validated PAT")
                    | PTE_NULL
            } else {
                result.empty(level)
            };
            for index in 0..512 {
                mem.write_entry(table, index, empty);
            }
            result.scratch[level as usize - 1] = table;
            result.tables += 1;
        }
        for index in 0..512 {
            mem.write_entry(result.root, index, result.empty(0));
        }
        Ok(result)
    }

    fn empty(&self, level: u8) -> u64 {
        if level == LEVEL_PT {
            if self.scratch[2] == 0 {
                return 0;
            }
            self.format
                .encode_ppgtt(0, self.null_pat, true)
                .expect("validated PAT")
                | PTE_NULL
        } else if self.scratch[level as usize] != 0 {
            encode_table_entry_with_pat(self.scratch[level as usize], self.table_pat)
                .expect("validated table")
        } else {
            0
        }
    }

    /// Physical address of the PML4 root — the value an
    /// execlists context programs into its PDP0 pair
    /// ([`crate::intel_gpu_rcs::RcsEngine::attach_ppgtt`]).
    pub fn root_phys(&self) -> u64 {
        self.root
    }

    /// Encoded PDP0/PTBP, including PRESENT, RW and the non-leaf PAT bits.
    pub fn root_descriptor(&self) -> u64 {
        // Creation/map validate the allocator's physical field.
        self.root | PTE_PRESENT | PTE_RW | ((self.table_pat as u64) << 3)
    }

    /// Table pages this PPGTT owns, root included.
    pub fn table_pages(&self) -> u32 {
        self.tables
    }

    /// Leaf pages currently mapped.
    pub fn mapped_pages(&self) -> u64 {
        self.mapped
    }

    /// Validate one entry read during a walk at `level` (leaf
    /// validation only at the PT level). Returns the next
    /// physical address to follow, or the outcome that stops
    /// the walk.
    fn follow(&self, entry: u64, level: u8) -> Result<u64, WalkOutcome> {
        if !pte_present(entry) {
            return Err(WalkOutcome::NotMapped { level });
        }
        let allowed = if level == LEVEL_PT {
            LEAF_ENTRY_ALLOWED
                | PTE_NULL
                | if self.format == PteFormat::XeLpg {
                    PTE_PAT3
                } else {
                    0
                }
        } else {
            TABLE_ENTRY_ALLOWED
        };
        let phys = pte_phys(entry);
        if entry & !allowed != 0 {
            return Err(WalkOutcome::Corrupt { level });
        }
        if level == LEVEL_PT && entry & PTE_NULL != 0 {
            return Err(if phys == 0 {
                WalkOutcome::Null
            } else {
                WalkOutcome::Corrupt { level }
            });
        }
        if phys == 0 {
            return Err(WalkOutcome::Corrupt { level });
        }
        Ok(phys)
    }

    /// Map the 4 KiB page at physical `phys` into the PPGTT at
    /// virtual `va`, creating intermediate tables on first use.
    /// Both addresses must be page-aligned; `phys` must fit the
    /// 46-bit GFX space. Mapping over a live leaf is
    /// [`PpgttError::AlreadyMapped`] — unmap first.
    pub fn map<M: PtMemory>(
        &mut self,
        mem: &mut M,
        va: u64,
        phys: u64,
        pat: PatSlot,
        writable: bool,
    ) -> Result<(), PpgttError> {
        self.map_with_pat(mem, va, phys, pat as u8, writable)
    }

    /// Full generation-specific PAT index (three bits on Gen12, four on
    /// Xe-LPG). The index names a PAT entry programmed by the GT owner.
    pub fn map_with_pat<M: PtMemory>(
        &mut self,
        mem: &mut M,
        va: u64,
        phys: u64,
        pat_index: u8,
        writable: bool,
    ) -> Result<(), PpgttError> {
        if va >= PPGTT_VA_SIZE {
            return Err(PpgttError::VaOutOfRange);
        }
        if va % GTT_PAGE_SIZE != 0 {
            return Err(PpgttError::Unaligned);
        }
        // Encode first: a bad physical address fails before any
        // table is created, leaving the tree untouched.
        let leaf = self.format.encode_ppgtt(phys, pat_index, writable)?;
        self.map_encoded(mem, va, leaf)
    }

    /// As [`Self::map_with_pat`] for a local-memory (VRAM) device address:
    /// sets XE_PPGTT_PTE_DM (bit 11), outside the PAT and address fields.
    pub fn map_device_with_pat<M: PtMemory>(
        &mut self,
        mem: &mut M,
        va: u64,
        device_address: u64,
        pat_index: u8,
        writable: bool,
    ) -> Result<(), PpgttError> {
        if va >= PPGTT_VA_SIZE {
            return Err(PpgttError::VaOutOfRange);
        }
        if va % GTT_PAGE_SIZE != 0 {
            return Err(PpgttError::Unaligned);
        }
        let leaf = self
            .format
            .encode_ppgtt(device_address, pat_index, writable)?
            | PTE_DM;
        self.map_encoded(mem, va, leaf)
    }

    pub fn map_null<M: PtMemory>(
        &mut self,
        mem: &mut M,
        va: u64,
        pat_index: u8,
    ) -> Result<(), PpgttError> {
        let leaf = self.format.encode_ppgtt(0, pat_index, true)? | PTE_NULL;
        self.map_encoded(mem, va, leaf)?;
        self.nulls.insert(va);
        Ok(())
    }

    fn map_encoded<M: PtMemory>(
        &mut self,
        mem: &mut M,
        va: u64,
        leaf: u64,
    ) -> Result<(), PpgttError> {
        if va >= PPGTT_VA_SIZE {
            return Err(PpgttError::VaOutOfRange);
        }
        if va % GTT_PAGE_SIZE != 0 {
            return Err(PpgttError::Unaligned);
        }
        let idx = va_indices(va);
        let mut table = self.root;
        for (level, &index) in idx.iter().enumerate().take(LEVEL_PT as usize) {
            let entry = mem.read_entry(table, index);
            if pte_present(entry) && (self.scratch[level] == 0 || entry != self.empty(level as u8))
            {
                // An existing intermediate entry must be
                // well-formed to descend into; a corrupt one is
                // not ours to overwrite silently.
                match self.follow(entry, level as u8) {
                    Ok(next) => table = next,
                    Err(WalkOutcome::Corrupt { level }) => {
                        return Err(PpgttError::CorruptEntry { level });
                    }
                    Err(_) => unreachable!("present entry cannot be NotMapped"),
                }
            } else {
                let new_table = mem.alloc_table()?;
                let encoded = match encode_table_entry_with_pat(new_table, self.table_pat) {
                    Ok(value) => value,
                    Err(error) => {
                        mem.free_table(new_table);
                        return Err(error.into());
                    }
                };
                let empty = self.empty(level as u8 + 1);
                if empty != 0 {
                    for index in 0..512 {
                        mem.write_entry(new_table, index, empty);
                    }
                }
                mem.write_entry(table, index, encoded);
                self.tables += 1;
                table = new_table;
            }
        }
        let existing = mem.read_entry(table, idx[LEVEL_PT as usize]);
        if pte_present(existing) && (existing != self.empty(LEVEL_PT) || self.nulls.contains(&va)) {
            return Err(PpgttError::AlreadyMapped);
        }
        mem.write_entry(table, idx[LEVEL_PT as usize], leaf);
        self.mapped += 1;
        Ok(())
    }

    /// Remove the mapping at `va`, returning the physical page
    /// that was mapped. Intermediate tables the unmap leaves
    /// empty are freed back to `mem` (the root always stays).
    pub fn unmap<M: PtMemory>(&mut self, mem: &mut M, va: u64) -> Result<u64, PpgttError> {
        if va >= PPGTT_VA_SIZE {
            return Err(PpgttError::VaOutOfRange);
        }
        if va % GTT_PAGE_SIZE != 0 {
            return Err(PpgttError::Unaligned);
        }
        let idx = va_indices(va);
        // Descend, recording the path for the pruning pass.
        let mut tables = [0u64; LEVELS];
        let mut table = self.root;
        for level in 0..LEVEL_PT as usize {
            tables[level] = table;
            let entry = mem.read_entry(table, idx[level]);
            match self.follow(entry, level as u8) {
                Ok(next) => table = next,
                Err(WalkOutcome::Corrupt { level }) => {
                    return Err(PpgttError::CorruptEntry { level });
                }
                Err(_) => return Err(PpgttError::NotMapped),
            }
        }
        tables[LEVEL_PT as usize] = table;
        let leaf = mem.read_entry(table, idx[LEVEL_PT as usize]);
        if !pte_present(leaf) || (leaf == self.empty(LEVEL_PT) && !self.nulls.contains(&va)) {
            return Err(PpgttError::NotMapped);
        }
        let phys = pte_phys(leaf);
        self.nulls.remove(&va);
        mem.write_entry(table, idx[LEVEL_PT as usize], self.empty(LEVEL_PT));
        self.mapped -= 1;
        // Prune empty tables bottom-up: a freed table's parent
        // entry is cleared, which may empty the parent in turn.
        for level in (1..LEVELS).rev() {
            let t = tables[level];
            let mut empty = true;
            for i in 0..ENTRIES_PER_TABLE {
                if mem.read_entry(t, i) != self.empty(level as u8) {
                    empty = false;
                    break;
                }
            }
            if !empty {
                break;
            }
            mem.write_entry(
                tables[level - 1],
                idx[level - 1],
                self.empty(level as u8 - 1),
            );
            mem.free_table(t);
            self.tables -= 1;
        }
        Ok(phys)
    }

    /// Walk `va` without allocating: the translation the
    /// hardware walker would produce, with the stopping level
    /// named when there is none.
    pub fn translate<M: PtMemory>(&self, mem: &M, va: u64) -> Result<WalkOutcome, PpgttError> {
        if va >= PPGTT_VA_SIZE {
            return Err(PpgttError::VaOutOfRange);
        }
        let idx = va_indices(va);
        let mut table = self.root;
        for (level, &index) in idx.iter().enumerate().take(LEVEL_PT as usize) {
            let entry = mem.read_entry(table, index);
            match self.follow(entry, level as u8) {
                Ok(next) => table = next,
                Err(outcome) => return Ok(outcome),
            }
        }
        let leaf = mem.read_entry(table, idx[LEVEL_PT as usize]);
        match self.follow(leaf, LEVEL_PT) {
            Ok(page) => Ok(WalkOutcome::Mapped(page | (va & 0xFFF))),
            Err(outcome) => Ok(outcome),
        }
    }

    /// Free every table this PPGTT owns, root last. Mappings
    /// are abandoned, not unmapped one by one; leaf frames were
    /// never ours to free.
    pub fn teardown<M: PtMemory>(self, mem: &mut M) {
        Self::free_subtree(mem, self.root, LEVEL_PML4, &self.scratch);
        for table in self.scratch {
            if table != 0 {
                mem.free_table(table);
            }
        }
    }

    fn free_subtree<M: PtMemory>(mem: &mut M, table: u64, level: u8, scratch: &[u64; 3]) {
        if level < LEVEL_PT {
            let mut children = Vec::new();
            for i in 0..ENTRIES_PER_TABLE {
                let entry = mem.read_entry(table, i);
                if pte_present(entry) && pte_phys(entry) != 0 && !scratch.contains(&pte_phys(entry))
                {
                    children.push(pte_phys(entry));
                }
            }
            for child in children {
                Self::free_subtree(mem, child, level + 1, scratch);
            }
        }
        mem.free_table(table);
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the PPGTT walker. The fake physical memory
    //! is a *model of system RAM*, not of the walker: table
    //! pages live at physical addresses in a byte store, and an
    //! independent reference walk — written directly from the
    //! PRM level/index definition, sharing no code with the
    //! production walker — cross-checks every translation. One
    //! full chain is pinned byte-for-byte against hand-computed
    //! PRM entry values.

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// First physical address the fake RAM hands out.
    const FAKE_PHYS_BASE: u64 = 0x4000_0000;

    fn smoke_null_scratch_tree_isolation_and_reclamation() -> TestResult {
        let mut mem = FakePtMemory::new();
        let mut vm = Ppgtt::with_scratch(&mut mem, PteFormat::XeLpg, 2, 3).unwrap();
        assert_eq!(vm.table_pages(), 4);
        assert_eq!(mem.live, 4);
        // Fixed wire values: scratch PT is first after root, WB PAT3+RW+NULL.
        assert_eq!(mem.raw_read(FAKE_PHYS_BASE + 4096, 17), 0x21b);
        for va in [0, 0x1234_5678, (1u64 << 48) - 1] {
            assert_eq!(vm.translate(&mem, va), Ok(WalkOutcome::Null));
        }
        vm.map_with_pat(&mut mem, 0x1234_0000_0000, 0x1000_0000, 3, true)
            .unwrap();
        assert_eq!(vm.table_pages(), 7);
        assert_eq!(
            vm.translate(&mem, 0x1234_0000_0080),
            Ok(WalkOutcome::Mapped(0x1000_0080))
        );
        assert_eq!(vm.translate(&mem, 0x1234_0000_1080), Ok(WalkOutcome::Null));
        assert_eq!(vm.translate(&mem, 0x2234_0000_0080), Ok(WalkOutcome::Null));
        assert_eq!(vm.unmap(&mut mem, 0x1234_0000_0000), Ok(0x1000_0000));
        assert_eq!(vm.table_pages(), 4);
        assert_eq!(
            vm.unmap(&mut mem, 0x1234_0000_0000),
            Err(PpgttError::NotMapped)
        );
        vm.map_null(&mut mem, 0x1234_0000_0000, 3).unwrap();
        assert_eq!(
            vm.map_with_pat(&mut mem, 0x1234_0000_0000, 0x1000_0000, 3, true),
            Err(PpgttError::AlreadyMapped)
        );
        assert_eq!(vm.unmap(&mut mem, 0x1234_0000_0000), Ok(0));
        vm.teardown(&mut mem);
        assert_eq!(mem.live, 0);
        for limit in 1..4 {
            let mut mem = FakePtMemory::new();
            mem.limit = limit;
            assert!(Ppgtt::with_scratch(&mut mem, PteFormat::XeLpg, 2, 3).is_err());
            assert_eq!(mem.live, 0);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_ppgtt",
        smoke_null_scratch_tree_isolation_and_reclamation
    );

    struct FakePtMemory {
        pages: BTreeMap<u64, Rc<RefCell<alloc::vec::Vec<u8>>>>,
        free_list: alloc::vec::Vec<u64>,
        next: u64,
        live: u32,
        limit: u32,
    }

    impl FakePtMemory {
        fn new() -> Self {
            Self {
                pages: BTreeMap::new(),
                free_list: alloc::vec::Vec::new(),
                next: FAKE_PHYS_BASE,
                live: 0,
                limit: u32::MAX,
            }
        }
        /// Write a raw entry directly into fake RAM — the
        /// tamper path: it bypasses the walker's encoders the
        /// way a foreign writer of the table would.
        fn raw_write(&mut self, table: u64, index: usize, val: u64) {
            self.write_entry(table, index, val);
        }
        fn raw_read(&self, table: u64, index: usize) -> u64 {
            self.read_entry(table, index)
        }
    }

    impl PtMemory for FakePtMemory {
        fn alloc_table(&mut self) -> Result<u64, PpgttError> {
            if self.live >= self.limit {
                return Err(PpgttError::OutOfMemory);
            }
            let phys = match self.free_list.pop() {
                Some(p) => p,
                None => {
                    let p = self.next;
                    self.next += GTT_PAGE_SIZE;
                    p
                }
            };
            self.pages
                .insert(phys, Rc::new(RefCell::new(alloc::vec![0u8; 4096])));
            self.live += 1;
            Ok(phys)
        }
        fn free_table(&mut self, phys: u64) {
            if self.pages.remove(&phys).is_some() {
                self.free_list.push(phys);
                self.live -= 1;
            }
        }
        fn read_entry(&self, table_phys: u64, index: usize) -> u64 {
            let page = self
                .pages
                .get(&table_phys)
                .expect("fake RAM: read of unallocated table");
            let m = page.borrow();
            let off = index * 8;
            u64::from_le_bytes(m[off..off + 8].try_into().unwrap())
        }
        fn write_entry(&mut self, table_phys: u64, index: usize, val: u64) {
            let page = self
                .pages
                .get(&table_phys)
                .expect("fake RAM: write of unallocated table");
            let mut m = page.borrow_mut();
            let off = index * 8;
            m[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
        fn live_tables(&self) -> u32 {
            self.live
        }
    }

    /// Independent reference walk, written from the PRM
    /// definition alone (shifts 39/30/21/12, 9-bit indices,
    /// supported phys bits 45:12, PRESENT bit 0). Shares no code with the
    /// production walker.
    fn ref_translate(mem: &FakePtMemory, root: u64, va: u64) -> Option<u64> {
        let mut table = root;
        for shift in [39u32, 30, 21] {
            let e = mem.read_entry(table, ((va >> shift) & 0x1FF) as usize);
            if e & 1 == 0 {
                return None;
            }
            table = e & 0x0000_3FFF_FFFF_F000;
        }
        let e = mem.read_entry(table, ((va >> 12) & 0x1FF) as usize);
        if e & 1 == 0 {
            return None;
        }
        Some((e & 0x0000_3FFF_FFFF_F000) | (va & 0xFFF))
    }

    fn smoke_ppgtt_nonleaf_cache_policy() -> TestResult {
        // xe_vm.c::pde_encode_pat_index/xelp_pde_encode_bo: low two PAT
        // bits occupy 4:3 at every non-leaf and in the context root descriptor.
        for pat in 0..=3 {
            let mut memory = FakePtMemory::new();
            let mut vm = Ppgtt::with_table_pat(&mut memory, PteFormat::XeLpg, pat).unwrap();
            let root = vm.root_phys();
            assert_eq!(vm.root_descriptor(), root | 3 | ((pat as u64) << 3));
            vm.map_with_pat(&mut memory, 0x1234_0000_0000, 0x12345000, 9, false)
                .unwrap();
            let mut page = root;
            for index in [36, 208, 0] {
                let entry = memory.raw_read(page, index);
                assert_eq!(entry & 0xfff, 3 | ((pat as u64) << 3));
                page = entry & 0x0000_3fff_ffff_f000;
            }
            assert_eq!(memory.raw_read(page, 0), 0x4000_0000_1234_5009);
            assert_eq!(
                vm.translate(&memory, 0x1234_0000_0123),
                Ok(WalkOutcome::Mapped(0x12345123))
            );
            assert_eq!(vm.unmap(&mut memory, 0x1234_0000_0000), Ok(0x12345000));
            assert_eq!(memory.live_tables(), 1);
            vm.teardown(&mut memory);
            assert_eq!(memory.live_tables(), 0);
        }
        let mut memory = FakePtMemory::new();
        assert!(matches!(
            Ppgtt::with_table_pat(&mut memory, PteFormat::XeLpg, 4),
            Err(PpgttError::InvalidPatIndex)
        ));
        assert_eq!(memory.live_tables(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_ppgtt",
        smoke_ppgtt_nonleaf_cache_policy
    );

    fn smoke_ppgtt_va_decomposition() -> TestResult {
        // Hand-decomposed: indices 3 / 5 / 7 / 9, offset 0xABC.
        let va = (3u64 << 39) | (5 << 30) | (7 << 21) | (9 << 12) | 0xABC;
        if va_indices(va) != [3, 5, 7, 9] {
            return TestResult::Fail("VA decomposition disagrees with the PRM levels");
        }
        if va_indices(0) != [0, 0, 0, 0] {
            return TestResult::Fail("zero VA must decompose to zero indices");
        }
        if va_indices(PPGTT_VA_SIZE - GTT_PAGE_SIZE) != [511, 511, 511, 511] {
            return TestResult::Fail("top VA must decompose to all-511 indices");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_ppgtt", smoke_ppgtt_va_decomposition);

    fn smoke_ppgtt_map_translate_roundtrip() -> TestResult {
        let mut mem = FakePtMemory::new();
        let mut vm = match Ppgtt::new(&mut mem) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("ppgtt create"),
        };
        // The fake hands tables out in order from FAKE_PHYS_BASE,
        // so the chain for this VA is fully determined — pin
        // every entry byte-for-byte against the PRM encoding.
        let va = (3u64 << 39) | (5 << 30) | (7 << 21) | (9 << 12);
        let phys = 0x0000_0000_00C0_F000u64;
        if vm.map(&mut mem, va, phys, PatSlot::Slot1, true).is_err() {
            return TestResult::Fail("map");
        }
        if vm.root_phys() != FAKE_PHYS_BASE {
            return TestResult::Fail("root must be the first table");
        }
        if mem.raw_read(vm.root_phys(), 3) != (FAKE_PHYS_BASE + 0x1000) | 3 {
            return TestResult::Fail("PML4 entry must be PDPT phys | PRESENT");
        }
        if mem.raw_read(FAKE_PHYS_BASE + 0x1000, 5) != (FAKE_PHYS_BASE + 0x2000) | 3 {
            return TestResult::Fail("PDPT entry must be PD phys | PRESENT");
        }
        if mem.raw_read(FAKE_PHYS_BASE + 0x2000, 7) != (FAKE_PHYS_BASE + 0x3000) | 3 {
            return TestResult::Fail("PD entry must be PT phys | PRESENT");
        }
        // Leaf: PRESENT | RW | phys | PAT index 1 (bit 3)
        // for a writable mapping — hand-computed literal.
        if mem.raw_read(FAKE_PHYS_BASE + 0x3000, 9) != 0x0000_0000_00C0_F00B {
            return TestResult::Fail("leaf entry disagrees with the PRM PTE layout");
        }
        match vm.translate(&mem, va + 0x123) {
            Ok(WalkOutcome::Mapped(p)) if p == phys + 0x123 => {}
            _ => return TestResult::Fail("translate must return phys + offset"),
        }
        if ref_translate(&mem, vm.root_phys(), va + 0x123) != Some(phys + 0x123) {
            return TestResult::Fail("reference walk disagrees with production walk");
        }
        if vm.table_pages() != 4 || vm.mapped_pages() != 1 {
            return TestResult::Fail("accounting: one chain = 4 tables, 1 leaf");
        }
        if mem.live_tables() != 4 {
            return TestResult::Fail("allocator accounting disagrees");
        }
        vm.teardown(&mut mem);
        if mem.live_tables() != 0 {
            return TestResult::Fail("teardown must release every table");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_ppgtt",
        smoke_ppgtt_map_translate_roundtrip
    );

    fn smoke_ppgtt_boundary_crossings() -> TestResult {
        let mut mem = FakePtMemory::new();
        let mut vm = match Ppgtt::new(&mut mem) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("ppgtt create"),
        };
        // Last page of one PT and first page of the next PD
        // entry; last page of a PDPT span and the first of the
        // next; the very top page of the 48-bit space.
        let cases: [(u64, u64); 5] = [
            ((1 << 21) - GTT_PAGE_SIZE, 0x1000_0000),
            (1 << 21, 0x1001_0000),
            ((1 << 30) - GTT_PAGE_SIZE, 0x1002_0000),
            (1 << 30, 0x1003_0000),
            (PPGTT_VA_SIZE - GTT_PAGE_SIZE, 0x1004_0000),
        ];
        for (va, phys) in cases {
            if vm.map(&mut mem, va, phys, PatSlot::Slot2, false).is_err() {
                return TestResult::Fail("boundary map refused");
            }
        }
        for (va, phys) in cases {
            match vm.translate(&mem, va + 0x77) {
                Ok(WalkOutcome::Mapped(p)) if p == phys + 0x77 => {}
                _ => return TestResult::Fail("boundary translate wrong"),
            }
            if ref_translate(&mem, vm.root_phys(), va + 0x77) != Some(phys + 0x77) {
                return TestResult::Fail("reference walk disagrees at a boundary");
            }
        }
        // The page just below a mapped boundary page is not
        // mapped (no off-by-one bleed across the boundary).
        match vm.translate(&mem, (1 << 21) - 2 * GTT_PAGE_SIZE) {
            Ok(WalkOutcome::NotMapped { level: LEVEL_PT }) => {}
            _ => return TestResult::Fail("neighbour page must be NotMapped at PT"),
        }
        vm.teardown(&mut mem);
        if mem.live_tables() != 0 {
            return TestResult::Fail("teardown balance");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_ppgtt",
        smoke_ppgtt_boundary_crossings
    );

    fn smoke_ppgtt_full_page_table_masking() -> TestResult {
        // Masking-defeating: fill every entry of one PT with a
        // distinct physical page. A walker that masked an index
        // wrong would alias entries and fail somewhere in 512.
        let mut mem = FakePtMemory::new();
        let mut vm = match Ppgtt::new(&mut mem) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("ppgtt create"),
        };
        let base_va = 0x40_0000u64; // PD index 2, PT indices 0..511
        for i in 0..512u64 {
            let phys = 0x2000_0000 + i * GTT_PAGE_SIZE;
            if vm
                .map(
                    &mut mem,
                    base_va + i * GTT_PAGE_SIZE,
                    phys,
                    PatSlot::Slot1,
                    true,
                )
                .is_err()
            {
                return TestResult::Fail("fill map refused");
            }
        }
        if vm.mapped_pages() != 512 {
            return TestResult::Fail("512 leaves must be accounted");
        }
        for i in 0..512u64 {
            let va = base_va + i * GTT_PAGE_SIZE + 0x5A;
            let expect = 0x2000_0000 + i * GTT_PAGE_SIZE + 0x5A;
            match vm.translate(&mem, va) {
                Ok(WalkOutcome::Mapped(p)) if p == expect => {}
                _ => return TestResult::Fail("full-table translate wrong"),
            }
            if ref_translate(&mem, vm.root_phys(), va) != Some(expect) {
                return TestResult::Fail("reference walk disagrees in full table");
            }
        }
        vm.teardown(&mut mem);
        if mem.live_tables() != 0 {
            return TestResult::Fail("teardown balance after full table");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_ppgtt",
        smoke_ppgtt_full_page_table_masking
    );

    fn smoke_ppgtt_unmap_and_prune() -> TestResult {
        let mut mem = FakePtMemory::new();
        let mut vm = match Ppgtt::new(&mut mem) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("ppgtt create"),
        };
        let va_a = (2u64 << 30) | (3 << 21) | (4 << 12);
        let va_b = va_a + GTT_PAGE_SIZE; // same PT, next leaf
        let va_far = (9u64 << 39) | (1 << 12); // disjoint chain
        for (va, phys) in [
            (va_a, 0x3000_0000u64),
            (va_b, 0x3001_0000),
            (va_far, 0x3002_0000),
        ] {
            if vm.map(&mut mem, va, phys, PatSlot::Slot1, true).is_err() {
                return TestResult::Fail("map");
            }
        }
        // Two chains: root + (PDPT,PD,PT) + (PDPT,PD,PT) = 7.
        if vm.table_pages() != 7 || mem.live_tables() != 7 {
            return TestResult::Fail("two chains must own 7 tables");
        }
        // Unmap one of two leaves sharing a PT: no table freed.
        match vm.unmap(&mut mem, va_a) {
            Ok(0x3000_0000) => {}
            _ => return TestResult::Fail("unmap must return the leaf phys"),
        }
        if vm.table_pages() != 7 {
            return TestResult::Fail("shared PT must survive a sibling unmap");
        }
        match vm.translate(&mem, va_b) {
            Ok(WalkOutcome::Mapped(0x3001_0000)) => {}
            _ => return TestResult::Fail("sibling mapping must survive"),
        }
        // Unmap the last leaf of the far chain: its whole chain
        // prunes back to the root.
        match vm.unmap(&mut mem, va_far) {
            Ok(0x3002_0000) => {}
            _ => return TestResult::Fail("far unmap"),
        }
        if vm.table_pages() != 4 || mem.live_tables() != 4 {
            return TestResult::Fail("empty chain must prune to root + one chain");
        }
        match vm.translate(&mem, va_far) {
            Ok(WalkOutcome::NotMapped { level: LEVEL_PML4 }) => {}
            _ => return TestResult::Fail("pruned chain must stop at the PML4"),
        }
        // Unmapping it again is an error, not a no-op.
        match vm.unmap(&mut mem, va_far) {
            Err(PpgttError::NotMapped) => {}
            _ => return TestResult::Fail("double unmap must be NotMapped"),
        }
        vm.teardown(&mut mem);
        if mem.live_tables() != 0 {
            return TestResult::Fail("teardown balance");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_ppgtt", smoke_ppgtt_unmap_and_prune);

    fn smoke_ppgtt_rejects_invalid() -> TestResult {
        let mut mem = FakePtMemory::new();
        let mut vm = match Ppgtt::new(&mut mem) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("ppgtt create"),
        };
        let va = 0x20_0000u64;
        match vm.map(&mut mem, PPGTT_VA_SIZE, 0x1000, PatSlot::Slot1, true) {
            Err(PpgttError::VaOutOfRange) => {}
            _ => return TestResult::Fail("VA at 2^48 must be refused"),
        }
        match vm.map(&mut mem, va + 1, 0x1000, PatSlot::Slot1, true) {
            Err(PpgttError::Unaligned) => {}
            _ => return TestResult::Fail("unaligned VA must be refused"),
        }
        match vm.map(&mut mem, va, 0x1800, PatSlot::Slot1, true) {
            Err(PpgttError::Unaligned) => {}
            _ => return TestResult::Fail("unaligned phys must be refused"),
        }
        match vm.map(&mut mem, va, 1u64 << 46, PatSlot::Slot1, true) {
            Err(PpgttError::PhysOutOfRange) => {}
            _ => return TestResult::Fail(">46-bit phys must be refused"),
        }
        // None of the refused maps may have created tables.
        if vm.table_pages() != 1 || mem.live_tables() != 1 {
            return TestResult::Fail("refused maps must leave the tree untouched");
        }
        if vm.map(&mut mem, va, 0x1000, PatSlot::Slot1, true).is_err() {
            return TestResult::Fail("clean map refused");
        }
        match vm.map(&mut mem, va, 0x2000, PatSlot::Slot1, true) {
            Err(PpgttError::AlreadyMapped) => {}
            _ => return TestResult::Fail("double map must be AlreadyMapped"),
        }
        match vm.translate(&mem, PPGTT_VA_SIZE) {
            Err(PpgttError::VaOutOfRange) => {}
            _ => return TestResult::Fail("translate past the space must be refused"),
        }
        vm.teardown(&mut mem);
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_ppgtt", smoke_ppgtt_rejects_invalid);

    fn smoke_ppgtt_tampered_entries_are_corrupt() -> TestResult {
        let mut mem = FakePtMemory::new();
        let mut vm = match Ppgtt::new(&mut mem) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("ppgtt create"),
        };
        let va = (1u64 << 39) | (2 << 30) | (3 << 21) | (4 << 12);
        if vm
            .map(&mut mem, va, 0x4000_0000, PatSlot::Slot1, true)
            .is_err()
        {
            return TestResult::Fail("map");
        }
        let root = vm.root_phys();
        let pdpt = pte_phys(mem.raw_read(root, 1));
        let pd = pte_phys(mem.raw_read(pdpt, 2));
        let pt = pte_phys(mem.raw_read(pd, 3));
        // (a) Reserved bit set in the PD entry (bit 5 is not
        // assigned by the GFX PTE definition): the walk must
        // stop Corrupt at the PD level, not follow the entry.
        // The PD entry is the one *in* the PD table (index 3,
        // pointing at the PT): `level` names the table that
        // holds the offending entry, the convention
        // `WalkOutcome` documents and the PML4/PT cases pin.
        let pd_entry = mem.raw_read(pd, 3);
        mem.raw_write(pd, 3, pd_entry | (1 << 5));
        match vm.translate(&mem, va) {
            Ok(WalkOutcome::Corrupt { level: LEVEL_PD }) => {}
            _ => return TestResult::Fail("reserved-bit PD entry must be Corrupt at PD"),
        }
        mem.raw_write(pd, 3, pd_entry);
        // (b) Same tamper one level up: the entry in the PDPT
        // (index 2, pointing at the PD) must stop the walk
        // Corrupt at the PDPT level.
        let pdpt_entry = mem.raw_read(pdpt, 2);
        mem.raw_write(pdpt, 2, pdpt_entry | (1 << 5));
        match vm.translate(&mem, va) {
            Ok(WalkOutcome::Corrupt { level: LEVEL_PDPT }) => {}
            _ => return TestResult::Fail("reserved-bit PDPT entry must be Corrupt at PDPT"),
        }
        mem.raw_write(pdpt, 2, pdpt_entry);
        // (c) Present leaf with a zero physical address.
        let leaf = mem.raw_read(pt, 4);
        mem.raw_write(pt, 4, PTE_PRESENT);
        match vm.translate(&mem, va) {
            Ok(WalkOutcome::Corrupt { level: LEVEL_PT }) => {}
            _ => return TestResult::Fail("zero-phys leaf must be Corrupt at PT"),
        }
        mem.raw_write(pt, 4, leaf);
        // (d) Reserved bit in the leaf (bit 46 is outside the
        // 46-bit phys field and unassigned in a leaf).
        mem.raw_write(pt, 4, leaf | (1 << 46));
        match vm.translate(&mem, va) {
            Ok(WalkOutcome::Corrupt { level: LEVEL_PT }) => {}
            _ => return TestResult::Fail("reserved-bit leaf must be Corrupt at PT"),
        }
        mem.raw_write(pt, 4, leaf);
        // Restored table walks clean again.
        match vm.translate(&mem, va) {
            Ok(WalkOutcome::Mapped(0x4000_0000)) => {}
            _ => return TestResult::Fail("restored table must walk clean"),
        }
        vm.teardown(&mut mem);
        if mem.live_tables() != 0 {
            return TestResult::Fail("teardown balance");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_ppgtt",
        smoke_ppgtt_tampered_entries_are_corrupt
    );

    fn smoke_ppgtt_oom_mid_map_is_consistent() -> TestResult {
        // Room for the root + one intermediate table only: the
        // map must fail OutOfMemory partway, and the partial
        // chain must stay well-formed (translate = NotMapped,
        // teardown balanced).
        let mut mem = FakePtMemory::new();
        mem.limit = 2;
        let mut vm = match Ppgtt::new(&mut mem) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("ppgtt create"),
        };
        let va = (1u64 << 39) | (2 << 30) | (3 << 21) | (4 << 12);
        match vm.map(&mut mem, va, 0x5000_0000, PatSlot::Slot1, true) {
            Err(PpgttError::OutOfMemory) => {}
            _ => return TestResult::Fail("map past the table budget must be OutOfMemory"),
        }
        match vm.translate(&mem, va) {
            Ok(WalkOutcome::NotMapped { .. }) => {}
            _ => return TestResult::Fail("partial chain must translate NotMapped"),
        }
        if ref_translate(&mem, vm.root_phys(), va).is_some() {
            return TestResult::Fail("reference walk must agree on the partial chain");
        }
        if vm.mapped_pages() != 0 {
            return TestResult::Fail("failed map must not count a leaf");
        }
        vm.teardown(&mut mem);
        if mem.live_tables() != 0 {
            return TestResult::Fail("teardown must free the partial chain too");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_ppgtt",
        smoke_ppgtt_oom_mid_map_is_consistent
    );
}
