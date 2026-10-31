//! Gen12 / Xe-LPG GPU page-table codecs.
//!
//! References: Intel PRM Memory Views; the MIT-licensed i915
//! `gt/intel_gtt.h`, `gt/gen8_ppgtt.c` and `gt/intel_ggtt.c` in Linux v6.12.
//! These distinguish GPU encodings from CPU page-table encodings.
//!
//! ## GTT vs PPGTT
//!
//! Gen12 has two page-table machineries:
//!
//! - **Global GTT** (GGTT) — a single flat page table mapping the
//!   GPU virtual address space to host physical addresses. Used
//!   by display planes and other "always-on" engines.
//! - **Per-process GTT** (PPGTT) — a 4-level page-table walker
//!   per command-streamer context. Used by the 3D / compute /
//!   media engines.
//!
//! Both use 64-bit entries, with different fields:
//!
//! ```text
//!                         Gen12                 Xe-LPG
//! GGTT system memory      physical | PRESENT    + PAT[1:0] in bits53:52
//! PPGTT 4KiB system       PRESENT, RW,           + PAT[3] in bit62
//!                         PAT[2:0] in bits7,4,3
//! PPGTT intermediate      physical | PRESENT | RW | PAT[1:0] in bits4:3
//! ```
//!
//! This implementation uses the common physical-address field 45:12 and
//! 4KiB system pages. Local memory, large pages and later architectures are
//! not admitted. There is no x86-style NX or LRU encoding in these entries.
//! PAT indices name table entries whose policy the GT owner must establish.
//!
//! ## Scope
//!
//! The PTE codec, plus the GGTT installation discipline the
//! Stage-4 driver core applies on top of it: every GGTT mapping
//! is bounds-checked against the GGTT size derived from the
//! actual GTTMMADR BAR length (never assumed), and every PTE
//! write burst is followed by a readback flush so the writes are
//! posted before the mapping is handed to hardware. The PPGTT
//! walker lives in [`crate::intel_gpu_ppgtt`].

// ── GGTT window layout (TGL PRM Vol. 5 §"GTTMMADR") ────────────

/// Byte offset of the GGTT PTE array inside BAR0 (`GTTMMADR`):
/// the low 8 MiB of the BAR are the register file, the array
/// occupies the rest of the BAR.
pub const GGTT_ARRAY_BASE: u64 = 0x80_0000;

/// GGTT virtual-address size in bytes, derived from the length
/// of the GTTMMADR BAR mapping: one 8-byte PTE per 4 KiB page
/// over the array half of the BAR. A 16 MiB BAR therefore yields
/// a 4 GiB GGTT; a BAR no longer than the register half yields
/// zero. Deriving the size from the mapping the probe actually
/// made is what keeps the bounds checks below honest on parts
/// whose BAR differs.
pub fn ggtt_va_size(bar_len: u64) -> u64 {
    if bar_len <= GGTT_ARRAY_BASE {
        return 0;
    }
    (bar_len - GGTT_ARRAY_BASE) / 8 * GTT_PAGE_SIZE
}

/// Refuse a GGTT mapping whose `[gtt_offset, gtt_offset +
/// size_bytes)` range escapes the GGTT window `bar_len` implies.
/// `gtt_offset` must be page-aligned.
pub fn check_ggtt_range(bar_len: u64, gtt_offset: u64, size_bytes: u64) -> Result<(), GttError> {
    if gtt_offset % GTT_PAGE_SIZE != 0 {
        return Err(GttError::OutOfBounds);
    }
    let end = gtt_offset
        .checked_add(size_bytes)
        .ok_or(GttError::OutOfBounds)?;
    if end > ggtt_va_size(bar_len) {
        return Err(GttError::OutOfBounds);
    }
    Ok(())
}

/// Posting flush for a burst of GGTT PTE writes: a compiler
/// fence plus a readback of the last PTE slot written. MMIO
/// writes to the GGTT array are posted; without the readback a
/// caller could hand the mapping to an engine (or a plane)
/// before the final PTEs are visible to it.
pub fn flush_ggtt_writes(gtt_mmadr: &narf_bus::bar::MmioRegion, last_pte_index: u64) {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let pte_offset = GGTT_ARRAY_BASE + last_pte_index * 8;
    // SAFETY: `gtt_mmadr` is the caller-mapped BAR0 (`GTTMMADR`)
    // region and `pte_offset` is the slot this module just wrote
    // (callers pass the index of their final write, which the
    // bounds check has proven in-range), so the read lands on an
    // 8-byte-aligned slot inside the GGTT PTE array.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        let _ = gtt_mmadr.read32(pte_offset);
    }
}

// ── PTE bit definitions (TGL PRM Vol. 5 §"GFX PTE Definition") ──

/// PRESENT bit — entry maps a valid page.
pub const PTE_PRESENT: u64 = 1 << 0;
/// Read/write bit — display plane scanout sets this clear (RO);
/// 3D/compute engines may set it.
pub const PTE_RW: u64 = 1 << 1;
/// PPGTT PAT index bit 0 (Gen12+).
pub const PTE_PAT0: u64 = 1 << 3;
/// PPGTT PAT index bit 1 (Gen12+).
pub const PTE_PAT1: u64 = 1 << 4;
/// PPGTT PAT index bit 2 (Gen12+).
pub const PTE_PAT2: u64 = 1 << 7;
/// PPGTT PAT index bit 3 (Meteor Lake / Xe-LPG).
pub const PTE_PAT3: u64 = 1 << 62;
/// Conservative common system-memory address field (bits 45:12).
/// Source: MIT i915 gt/intel_gtt.h GEN12_GGTT_PTE_ADDR_MASK.
pub const PTE_PHYS_MASK: u64 = 0x0000_3FFF_FFFF_F000;

/// Distinct GPU page-table formats. GGTT and PPGTT do not share a
/// cache encoding; neither has the x86 NX bit previously emitted here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PteFormat {
    Gen12,
    XeLpg,
}

impl PteFormat {
    pub fn encode_ggtt(self, phys: u64, pat_index: u8) -> Result<u64, GttError> {
        validate_phys(phys)?;
        if pat_index > 3 {
            return Err(GttError::InvalidPatIndex);
        }
        let pat = match self {
            Self::Gen12 => 0, // Gen8/Gen12 GGTT has no PAT index fields.
            Self::XeLpg => ((pat_index as u64 & 1) << 52) | ((pat_index as u64 & 2) << 52),
        };
        Ok(phys | PTE_PRESENT | pat)
    }

    pub fn encode_ppgtt(self, phys: u64, pat_index: u8, writable: bool) -> Result<u64, GttError> {
        validate_phys(phys)?;
        let max = match self {
            Self::Gen12 => 7,
            Self::XeLpg => 15,
        };
        if pat_index > max {
            return Err(GttError::InvalidPatIndex);
        }
        let pat = ((pat_index as u64 & 1) << 3)
            | ((pat_index as u64 & 2) << 3)
            | ((pat_index as u64 & 4) << 5)
            | ((pat_index as u64 & 8) << 59);
        Ok(phys | PTE_PRESENT | if writable { PTE_RW } else { 0 } | pat)
    }
}

fn validate_phys(phys: u64) -> Result<(), GttError> {
    if phys & 0xfff != 0 {
        return Err(GttError::UnalignedPhys);
    }
    if phys & !PTE_PHYS_MASK != 0 {
        return Err(GttError::PhysOutOfRange);
    }
    Ok(())
}

/// Page size — every Gen12 GTT entry maps a 4 KiB page.
pub const GTT_PAGE_SIZE: u64 = 0x1000;

/// A low-two-bit PAT index. Cache policy is defined by programmed PAT
/// registers, not by this numeric slot; callers must initialize that table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum PatSlot {
    Slot0 = 0,
    Slot1 = 1,
    Slot2 = 2,
    Slot3 = 3,
}

impl PatSlot {
    /// Pack the low two PPGTT PAT index bits.
    pub const fn encode(self) -> u64 {
        let v = self as u64;
        ((v & 1) << 3) | (((v >> 1) & 1) << 4)
    }
    pub const fn decode(pte: u64) -> Self {
        let lo = (pte >> 3) & 1;
        let hi = (pte >> 4) & 1;
        match (hi << 1) | lo {
            0 => PatSlot::Slot0,
            1 => PatSlot::Slot1,
            2 => PatSlot::Slot2,
            _ => PatSlot::Slot3,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GttError {
    /// Phys address isn't 4 KiB-aligned.
    UnalignedPhys,
    /// Phys address has bits set outside the supported 46-bit
    /// system-memory address field.
    PhysOutOfRange,
    /// Physical allocation failed.
    OutOfMemory,
    /// The requested GGTT range escapes the GGTT window implied
    /// by the actual GTTMMADR BAR length.
    OutOfBounds,
    /// PAT index cannot be represented by this generation/table format.
    InvalidPatIndex,
}

/// Gen12 system-memory GGTT entry. `pat` is ignored because this format
/// has no PAT bits; use PteFormat::XeLpg for Meteor/Arrow Lake GGTT entries.
pub fn encode_scanout_pte(phys: u64, _pat: PatSlot) -> Result<u64, GttError> {
    PteFormat::Gen12.encode_ggtt(phys, 0)
}

/// Gen12 PPGTT leaf. The boolean controls GPU write permission; Intel GPU
/// page tables do not provide the CPU-style NX permission formerly claimed.
pub fn encode_engine_pte(phys: u64, pat: PatSlot, writable: bool) -> Result<u64, GttError> {
    PteFormat::Gen12.encode_ppgtt(phys, pat as u8, writable)
}

/// PPGTT intermediate entry: physical address, PRESENT and RW. The
/// default page-directory cache policy is PAT index zero.
pub fn encode_table_entry(next_level_phys: u64) -> Result<u64, GttError> {
    encode_table_entry_with_pat(next_level_phys, 0)
}

/// Linux xe_vm.c::xelp_pde_encode_bo: non-leaf nodes and the context's
/// PDP4 descriptor have only two PAT bits, independently of leaf policy.
pub fn encode_table_entry_with_pat(next_level_phys: u64, pat: u8) -> Result<u64, GttError> {
    validate_phys(next_level_phys)?;
    if pat > 3 {
        return Err(GttError::InvalidPatIndex);
    }
    Ok(PTE_PRESENT | PTE_RW | next_level_phys | ((pat as u64 & 3) << 3))
}

/// Publish immutable system pages before a GPU page walk or batch fetch.
/// In particular, Xe-LPG table reads do not snoop CPU caches (xe_bo.c).
/// Callers must keep all pages owned and prevent CPU writes until retirement.
pub(crate) fn publish_system_pages<'a>(
    pages: impl Iterator<Item = &'a narf_memory::frame::PhysFrame>,
) -> bool {
    publish_system_phys(pages.map(|frame| frame.start_address()))
}

/// As [`publish_system_pages`] for retained pages (e.g. USERPTR pins) that
/// the caller keeps alive until retirement.
pub(crate) fn publish_system_phys(pages: impl Iterator<Item = narf_memory::PhysAddr>) -> bool {
    use core::sync::atomic::{compiler_fence, fence, Ordering};
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "x86_64")]
    let line = {
        let caps = narf_arch::x86_64::cache::caps();
        let line = caps.line_bytes as usize;
        if !caps.clflush || !line.is_power_of_two() || line > 4096 {
            return false;
        }
        line
    };
    for page in pages {
        let base = page.kernel_ptr::<u8>();
        #[cfg(target_arch = "x86_64")]
        for offset in (0..4096usize).step_by(line) {
            compiler_fence(Ordering::SeqCst);
            // SAFETY: callers supply their owned, direct-mapped physical pages;
            // CLFLUSH support and the cache-line stride were checked above.
            unsafe { narf_arch::x86_64::cache::clflush(base.add(offset)) };
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: the caller owns the entire mapped page.
        unsafe {
            narf_arch::aarch64::cache::clean_inval_to_poc(base as usize, 4096);
        }
        narf_scheduler::sleep_pumps::run();
    }
    fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
    true
}

/// Decode the phys-address portion of an existing PTE.
pub fn pte_phys(pte: u64) -> u64 {
    pte & PTE_PHYS_MASK
}

/// `true` iff the PTE has `PRESENT` set.
pub fn pte_present(pte: u64) -> bool {
    pte & PTE_PRESENT != 0
}

/// Write a sequence of PTEs into the GGTT window to map a contiguous
/// block of physical memory for scanout.
/// Returns the GTT offset (in bytes) where the mapping begins.
pub fn map_contiguous_scanout(
    gtt_mmadr: &narf_bus::bar::MmioRegion,
    start_phys: u64,
    size_bytes: u64,
) -> Result<u32, GttError> {
    // We arbitrarily pick a GTT offset of 16 MiB (0x1000000) for our scanout
    // to avoid colliding with whatever the UEFI GOP mapped lower down (often at 0).
    const SCANOUT_GTT_OFFSET: u64 = 0x100_0000;

    let pages = size_bytes.div_ceil(GTT_PAGE_SIZE);
    check_ggtt_range(gtt_mmadr.len, SCANOUT_GTT_OFFSET, pages * GTT_PAGE_SIZE)?;
    for i in 0..pages {
        let phys = start_phys + i * GTT_PAGE_SIZE;
        let pte = encode_scanout_pte(phys, PatSlot::Slot2)?;

        let pte_index = (SCANOUT_GTT_OFFSET / GTT_PAGE_SIZE) + i;
        let pte_offset = GGTT_ARRAY_BASE + pte_index * 8;

        // Write 64-bit PTE (as two 32-bit writes)
        // SAFETY: `gtt_mmadr` is the caller-mapped BAR0 (`GTTMMADR`) region.
        // `pte_offset` is `GGTT_ARRAY_BASE` (8 MiB into the BAR) plus
        // `pte_index * 8`, landing on an 8-byte-aligned slot inside the
        // GGTT PTE array — the bounds check above has proven the whole
        // range fits the GGTT window this BAR implies — so both
        // `pte_offset` and `pte_offset + 4` are in-range, naturally-aligned
        // 32-bit GGTT register writes.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            gtt_mmadr.write32(pte_offset, (pte & 0xFFFF_FFFF) as u32);
            gtt_mmadr.write32(pte_offset + 4, (pte >> 32) as u32);
        }
    }
    if pages > 0 {
        flush_ggtt_writes(gtt_mmadr, SCANOUT_GTT_OFFSET / GTT_PAGE_SIZE + pages - 1);
    }

    Ok(SCANOUT_GTT_OFFSET as u32)
}

/// Allocate `size_bytes` worth of 4 KiB frames and map them consecutively
/// into the GGTT, creating a contiguous GPU virtual address. Returns the
/// GTT offset and the first physical frame allocated.
pub fn alloc_coherent_scanout(
    gtt_mmadr: &narf_bus::bar::MmioRegion,
    size_bytes: u64,
) -> Result<(u32, alloc::vec::Vec<narf_memory::frame::PhysFrame>), GttError> {
    const SCANOUT_GTT_OFFSET: u64 = 0x100_0000;

    let pages = size_bytes.div_ceil(GTT_PAGE_SIZE);
    check_ggtt_range(gtt_mmadr.len, SCANOUT_GTT_OFFSET, pages * GTT_PAGE_SIZE)?;
    let mut frames = alloc::vec::Vec::with_capacity(pages as usize);

    for i in 0..pages {
        // Allocate a single 4 KiB frame.
        let frame = narf_memory::frame::alloc_frame().map_err(|_| GttError::OutOfMemory)?;
        frames.push(frame);

        let phys = frame.start_address().raw();
        let pte = encode_scanout_pte(phys, PatSlot::Slot2)?;

        let pte_index = (SCANOUT_GTT_OFFSET / GTT_PAGE_SIZE) + i;
        let pte_offset = GGTT_ARRAY_BASE + pte_index * 8;

        // Write 64-bit PTE (as two 32-bit writes)
        // SAFETY: `gtt_mmadr` is the caller-mapped BAR0 (`GTTMMADR`) region.
        // `pte_offset` is `GGTT_ARRAY_BASE` (8 MiB into the BAR) plus
        // `pte_index * 8`, landing on an 8-byte-aligned slot inside the
        // GGTT PTE array — the bounds check above has proven the whole
        // range fits the GGTT window this BAR implies — so both
        // `pte_offset` and `pte_offset + 4` are in-range, naturally-aligned
        // 32-bit GGTT register writes.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            gtt_mmadr.write32(pte_offset, (pte & 0xFFFF_FFFF) as u32);
            gtt_mmadr.write32(pte_offset + 4, (pte >> 32) as u32);
        }
    }
    if pages > 0 {
        flush_ggtt_writes(gtt_mmadr, SCANOUT_GTT_OFFSET / GTT_PAGE_SIZE + pages - 1);
    }

    Ok((SCANOUT_GTT_OFFSET as u32, frames))
}

/// A physically contiguous scanout allocation owned by the driver.
///
/// The legacy [`alloc_coherent_scanout`] allocates one frame at a
/// time: the GGTT range is contiguous but the CPU-side frames are
/// scattered, so the surface cannot be published to a linear
/// framebuffer consumer (the fb console writes linearly from one
/// physical base). This allocation comes from the buddy order
/// allocator instead — one contiguous block — so
/// `head.start_address()` is a valid linear base for the whole
/// surface. Lane 1 (#1010): the Intel probe uses this path and
/// stores the block in `IntelGpu`, giving the scanout an owner.
#[derive(Copy, Clone, Debug)]
pub struct ContiguousScanout {
    /// GGTT byte offset the surface is mapped at.
    pub gtt_offset: u32,
    /// First (and head) physical frame of the buddy block.
    pub head: narf_memory::frame::PhysFrame,
    /// Buddy order of the block (`size = 4096 << order` bytes).
    pub order: u8,
    /// Requested surface size in bytes (<= block size).
    pub size_bytes: u64,
}

impl ContiguousScanout {
    /// Host-physical base of the surface — the linear address a
    /// framebuffer-console consumer maps and writes.
    pub fn phys_base(&self) -> u64 {
        self.head.start_address().raw()
    }
}

/// Smallest buddy order whose block holds `size_bytes`.
/// `None` when the request exceeds the buddy maximum
/// (`MAX_ORDER` = 13, a 32 MiB block).
pub fn scanout_order_for(size_bytes: u64) -> Option<u8> {
    let pages = size_bytes.div_ceil(GTT_PAGE_SIZE);
    let mut order = 0u8;
    while (1u64 << order) < pages {
        order += 1;
        if order > 13 {
            return None;
        }
    }
    Some(order)
}

/// The GGTT offset of the historical single-scanout window
/// (Pipe A's window in the multi-pipe assignment,
/// `intel_gpu_multipipe::scanout_gtt_offset`).
pub const SCANOUT_GTT_OFFSET_PIPE_A: u64 = 0x100_0000;

/// Allocate one physically contiguous block of frames and map it
/// into the GGTT at the scanout offset. On any failure after the
/// block is allocated, the block is freed before returning.
pub fn alloc_contiguous_scanout(
    gtt_mmadr: &narf_bus::bar::MmioRegion,
    size_bytes: u64,
) -> Result<ContiguousScanout, GttError> {
    alloc_contiguous_scanout_at(gtt_mmadr, SCANOUT_GTT_OFFSET_PIPE_A, size_bytes)
}

/// [`alloc_contiguous_scanout`] at a caller-chosen GGTT offset.
///
/// The single-offset original could only ever host one live
/// scanout: a second call remapped the same GGTT window onto new
/// frames, silently stealing the first surface. Multi-pipe
/// display (#1017) gives each pipe its own window (32 MiB apart,
/// the maximum scanout block) and allocates through here.
pub fn alloc_contiguous_scanout_at(
    gtt_mmadr: &narf_bus::bar::MmioRegion,
    gtt_offset: u64,
    size_bytes: u64,
) -> Result<ContiguousScanout, GttError> {
    alloc_contiguous_scanout_with_format(gtt_mmadr, gtt_offset, size_bytes, PteFormat::Gen12, 0)
}

/// Allocate a scanout using the generation's GGTT format and an already
/// programmed PAT index (Xe-LPG only). No PAT policy is inferred from a slot.
pub fn alloc_contiguous_scanout_with_format(
    gtt_mmadr: &narf_bus::bar::MmioRegion,
    gtt_offset: u64,
    size_bytes: u64,
    format: PteFormat,
    pat_index: u8,
) -> Result<ContiguousScanout, GttError> {
    if size_bytes == 0 || gtt_offset % GTT_PAGE_SIZE != 0 || gtt_offset > u32::MAX as u64 {
        return Err(GttError::OutOfBounds);
    }
    format.encode_ggtt(0, pat_index)?;
    let order = scanout_order_for(size_bytes).ok_or(GttError::OutOfMemory)?;
    let pages = size_bytes.div_ceil(GTT_PAGE_SIZE);
    check_ggtt_range(gtt_mmadr.len, gtt_offset, pages * GTT_PAGE_SIZE)?;
    let head = narf_memory::frame::alloc_pages_on(0, order).map_err(|_| GttError::OutOfMemory)?;
    let base = head.start_address().raw();
    for i in 0..pages {
        let phys = base + i * GTT_PAGE_SIZE;
        let pte = match format.encode_ggtt(phys, pat_index) {
            Ok(p) => p,
            Err(e) => {
                narf_memory::frame::free_pages(head, order);
                return Err(e);
            }
        };
        let pte_index = (gtt_offset / GTT_PAGE_SIZE) + i;
        let pte_offset = GGTT_ARRAY_BASE + pte_index * 8;
        // SAFETY: `gtt_mmadr` is the caller-mapped BAR0 (`GTTMMADR`) region.
        // `pte_offset` is `GGTT_ARRAY_BASE` (8 MiB into the BAR) plus
        // `pte_index * 8`, landing on an 8-byte-aligned slot inside the
        // GGTT PTE array — the bounds check above has proven the whole
        // range fits the GGTT window this BAR implies — so both
        // `pte_offset` and `pte_offset + 4` are in-range, naturally-aligned
        // 32-bit GGTT register writes.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            gtt_mmadr.write32(pte_offset, (pte & 0xFFFF_FFFF) as u32);
            gtt_mmadr.write32(pte_offset + 4, (pte >> 32) as u32);
        }
    }
    if pages > 0 {
        flush_ggtt_writes(gtt_mmadr, gtt_offset / GTT_PAGE_SIZE + pages - 1);
    }
    Ok(ContiguousScanout {
        gtt_offset: gtt_offset as u32,
        head,
        order,
        size_bytes,
    })
}

/// Return a contiguous scanout block to the frame allocator.
pub fn free_contiguous_scanout(alloc: &ContiguousScanout) {
    narf_memory::frame::free_pages(alloc.head, alloc.order);
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_scanout_order_sizing() -> TestResult {
        if scanout_order_for(4096) != Some(0) {
            return TestResult::Fail("one page must be order 0");
        }
        if scanout_order_for(4097) != Some(1) {
            return TestResult::Fail("two pages must be order 1");
        }
        // 1920x1080 XRGB padded surface: 7680 * 1080 = 8,294,400 B -> 2025 pages -> order 11.
        if scanout_order_for(8_294_400) != Some(11) {
            return TestResult::Fail("1080p surface must be order 11");
        }
        if scanout_order_for(32 * 1024 * 1024) != Some(13) {
            return TestResult::Fail("32 MiB must be order 13 (MAX_ORDER)");
        }
        if scanout_order_for(32 * 1024 * 1024 + 4096).is_some() {
            return TestResult::Fail(">32 MiB must not resolve to an order");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_scanout_order_sizing);

    fn smoke_pat_slot_round_trip() -> TestResult {
        for slot in [
            PatSlot::Slot0,
            PatSlot::Slot1,
            PatSlot::Slot2,
            PatSlot::Slot3,
        ] {
            let bits = slot.encode();
            if PatSlot::decode(bits) != slot {
                return TestResult::Fail("PAT slot encode/decode round-trip");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_pat_slot_round_trip);

    fn smoke_scanout_pte_layout() -> TestResult {
        let phys = 0x0000_0001_2345_6000u64;
        let pte = match encode_scanout_pte(phys, PatSlot::Slot2) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        if !pte_present(pte) {
            return TestResult::Fail("PRESENT bit not set");
        }
        if pte_phys(pte) != phys {
            return TestResult::Fail("phys round-trip");
        }
        if pte != 0x0000_0001_2345_6001 {
            return TestResult::Fail("Gen12 GGTT has no PAT bits");
        }
        if pte & PTE_RW != 0 {
            return TestResult::Fail("scanout PTE must be RO");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_scanout_pte_layout);

    fn smoke_engine_pte_permissions() -> TestResult {
        if encode_engine_pte(0x1000, PatSlot::Slot1, false) != Ok(0x1009)
            || encode_engine_pte(0x1000, PatSlot::Slot1, true) != Ok(0x100b)
        {
            return TestResult::Fail("PPGTT PAT/RW fields must use GPU encoding");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_engine_pte_permissions);

    fn smoke_xelpg_and_gen12_page_table_vectors() -> TestResult {
        // MIT i915 gt/intel_gtt.h + gen8_ppgtt.c + intel_ggtt.c:
        // PPGTT PAT[2:0] = bits7,4,3; MTL adds PAT3 at62.
        // MTL GGTT PAT[1:0] = bits53,52; Gen12 GGTT ignores PAT.
        let phys = 0x0000_0123_4567_8000;
        let cases = [
            (PteFormat::Gen12.encode_ggtt(phys, 3), 0x0000_0123_4567_8001),
            (PteFormat::XeLpg.encode_ggtt(phys, 3), 0x0030_0123_4567_8001),
            (
                PteFormat::Gen12.encode_ppgtt(phys, 7, true),
                0x0000_0123_4567_809b,
            ),
            (
                PteFormat::XeLpg.encode_ppgtt(phys, 15, true),
                0x4000_0123_4567_809b,
            ),
            (
                PteFormat::XeLpg.encode_ppgtt(phys, 8, false),
                0x4000_0123_4567_8001,
            ),
        ];
        for (actual, expected) in cases {
            if actual != Ok(expected) {
                return TestResult::Fail("GPU page-table reference vector");
            }
        }
        if PteFormat::Gen12.encode_ppgtt(phys, 8, true) != Err(GttError::InvalidPatIndex)
            || PteFormat::XeLpg.encode_ppgtt(phys, 16, true) != Err(GttError::InvalidPatIndex)
            || PteFormat::XeLpg.encode_ggtt(phys, 4) != Err(GttError::InvalidPatIndex)
        {
            return TestResult::Fail("unrepresentable PAT index admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gtt",
        smoke_xelpg_and_gen12_page_table_vectors
    );

    fn smoke_pte_rejects_unaligned_phys() -> TestResult {
        match encode_scanout_pte(0x1234, PatSlot::Slot2) {
            Err(GttError::UnalignedPhys) => TestResult::Pass,
            _ => TestResult::Fail("non-4KiB phys must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gtt",
        smoke_pte_rejects_unaligned_phys
    );

    fn smoke_pte_rejects_out_of_range_phys() -> TestResult {
        // Bit 46 set — outside the supported physical field.
        match encode_scanout_pte(1u64 << 46, PatSlot::Slot2) {
            Err(GttError::PhysOutOfRange) => TestResult::Pass,
            _ => TestResult::Fail(">46-bit phys must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gtt",
        smoke_pte_rejects_out_of_range_phys
    );

    fn smoke_table_entry_encoding() -> TestResult {
        // Byte-for-byte pin: a table entry is PRESENT | RW | phys, in
        // the same GFX PTE layout as a leaf (PRM Vol. 5).
        match encode_table_entry(0x0000_0001_2345_6000) {
            Ok(0x0000_0001_2345_6003) => {}
            _ => return TestResult::Fail("table entry must be phys | PRESENT | RW"),
        }
        match encode_table_entry(0x1234) {
            Err(GttError::UnalignedPhys) => {}
            _ => return TestResult::Fail("unaligned table phys must be rejected"),
        }
        match encode_table_entry(1u64 << 46) {
            Err(GttError::PhysOutOfRange) => {}
            _ => return TestResult::Fail(">46-bit table phys must be rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_table_entry_encoding);

    fn smoke_ggtt_va_size_from_bar_len() -> TestResult {
        // The canonical Gen12 GTTMMADR BAR is 16 MiB: 8 MiB of
        // PTE array = 1M entries = a 4 GiB GGTT.
        if ggtt_va_size(0x100_0000) != 0x1_0000_0000 {
            return TestResult::Fail("16 MiB BAR must imply a 4 GiB GGTT");
        }
        if ggtt_va_size(0x80_0000) != 0 {
            return TestResult::Fail("register-half-only BAR must imply no GGTT");
        }
        if ggtt_va_size(0x40_0000) != 0 {
            return TestResult::Fail("short BAR must imply no GGTT");
        }
        // 12 MiB BAR: 4 MiB of array = 512K entries = 2 GiB.
        if ggtt_va_size(0xC0_0000) != 0x8000_0000 {
            return TestResult::Fail("12 MiB BAR must imply a 2 GiB GGTT");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_ggtt_va_size_from_bar_len);

    fn smoke_ggtt_range_check_bounds() -> TestResult {
        let bar = 0x100_0000u64; // 4 GiB GGTT
        if check_ggtt_range(bar, 0x100_0000, 0x80_0000).is_err() {
            return TestResult::Fail("scanout range inside the GGTT refused");
        }
        // Last page of the GGTT exactly fits; one page past it not.
        if check_ggtt_range(bar, 0xFFFF_F000, 0x1000).is_err() {
            return TestResult::Fail("final GGTT page refused");
        }
        match check_ggtt_range(bar, 0xFFFF_F000, 0x2000) {
            Err(GttError::OutOfBounds) => {}
            _ => return TestResult::Fail("range past the GGTT end must be refused"),
        }
        // The fixed 16 MiB scanout offset against a BAR whose
        // GGTT is smaller than the offset: refused, where the old
        // unchecked code wrote blindly.
        match check_ggtt_range(0x80_8000, 0x100_0000, 0x1000) {
            Err(GttError::OutOfBounds) => {}
            _ => return TestResult::Fail("scanout offset past a small GGTT must be refused"),
        }
        match check_ggtt_range(bar, 0x100_0800, 0x1000) {
            Err(GttError::OutOfBounds) => {}
            _ => return TestResult::Fail("unaligned GGTT offset must be refused"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_ggtt_range_check_bounds);

    fn smoke_ggtt_scanout_map_bounds_and_readback() -> TestResult {
        // A fake 16 MiB GTTMMADR BAR over plain memory: the PTE
        // writes and the flush readback land in the backing store
        // exactly where the PRM layout puts them.
        let mut backing = alloc::vec![0u8; 0x100_0000];
        let region = narf_bus::bar::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: backing.as_mut_ptr() as u64,
            len: backing.len() as u64,
            kind: narf_bus::bar::BarKind::Mmio64 {
                prefetchable: false,
            },
        };
        let phys = 0x0000_0000_2345_6000u64;
        if map_contiguous_scanout(&region, phys, 2 * GTT_PAGE_SIZE).is_err() {
            return TestResult::Fail("in-bounds scanout map refused");
        }
        let expect = match encode_scanout_pte(phys, PatSlot::Slot2) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("pte encode"),
        };
        let slot = (GGTT_ARRAY_BASE + (0x100_0000 / GTT_PAGE_SIZE) * 8) as usize;
        let got = u64::from_le_bytes(backing[slot..slot + 8].try_into().unwrap());
        if got != expect {
            return TestResult::Fail("first scanout PTE not at the PRM slot");
        }
        let slot2 = slot + 8;
        let got2 = u64::from_le_bytes(backing[slot2..slot2 + 8].try_into().unwrap());
        let expect2 = match encode_scanout_pte(phys + GTT_PAGE_SIZE, PatSlot::Slot2) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("pte encode 2"),
        };
        if got2 != expect2 {
            return TestResult::Fail("second scanout PTE not contiguous");
        }
        // A BAR too small for the fixed scanout offset: refused
        // before any write (backing stays zero at the slot the
        // unchecked code would have hit).
        let mut small = alloc::vec![0u8; 0x80_8000];
        let small_region = narf_bus::bar::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: small.as_mut_ptr() as u64,
            len: small.len() as u64,
            kind: narf_bus::bar::BarKind::Mmio64 {
                prefetchable: false,
            },
        };
        match map_contiguous_scanout(&small_region, phys, GTT_PAGE_SIZE) {
            Err(GttError::OutOfBounds) => {}
            _ => return TestResult::Fail("small-BAR scanout map must be refused"),
        }
        if small.iter().any(|b| *b != 0) {
            return TestResult::Fail("refused map must not write any PTE");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gtt",
        smoke_ggtt_scanout_map_bounds_and_readback
    );
}
