//! GTT / PPGTT page-table entry codec — clean-room.
//!
//! Reference: **Tiger Lake PRM Vol. 5 §"Memory Views"**.
//! Cross-checked against ADL / RPL PRMs (same Gen12 PTE layout)
//! and the Meteor Lake PRM Vol. 5 (extended cache-control bits
//! noted but the legacy PTE encoding still works for KMS-grade
//! scanout).
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
//! Both share the same **64-bit page-table-entry layout** — only
//! the placement (single flat table vs 4-level walk) differs.
//!
//! ## PTE format (Gen12, 64-bit)
//!
//! ```text
//!   bit 0     PRESENT       — entry is valid.
//!   bit 1     RW            — read/write (display planes set 0; engines may set 1).
//!   bits 2-3  PWT/PCD       — legacy x86 cache-control mirrors.
//!   bit 6     LRU age       — 0=fresh, 1=aged.
//!   bits 7-11 reserved
//!   bits 12-38 phys[38:12]  — 4 KiB-aligned physical address.
//!   bit 60    PAT[0]        — selects PAT (page-attribute table) entry.
//!   bit 61    PAT[1]        — combined: 4 PAT slots → 4 cache modes.
//!   bit 62    LRU bypass    — when set, this page bypasses LRU.
//!   bit 63    NX            — no-execute (PPGTT only; GGTT ignores).
//! ```
//!
//! Source: TGL PRM Vol. 5 §"GFX PTE Definition".
//!
//! ## Scope
//!
//! The PTE codec, plus the GGTT installation discipline the
//! Stage-4 driver core applies on top of it: every GGTT mapping
//! is bounds-checked against the GGTT size derived from the
//! actual GTTMMADR BAR length (never assumed), and every PTE
//! write burst is followed by a readback flush so the writes are
//! posted before the mapping is handed to hardware. The PPGTT
//! walker lives in [`crate::intel_gpu_ppgtt`]; it shares this
//! entry format through [`encode_table_entry`].

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
/// PWT — legacy x86 PAT-bit-0 mirror.
pub const PTE_PWT: u64 = 1 << 3;
/// PCD — legacy x86 PAT-bit-1 mirror.
pub const PTE_PCD: u64 = 1 << 4;
/// LRU age bit — set on PTE eviction candidates.
pub const PTE_LRU_AGE: u64 = 1 << 6;
/// PAT bit 0 (selects PAT slot, low bit).
pub const PTE_PAT0: u64 = 1 << 60;
/// PAT bit 1 (selects PAT slot, high bit).
pub const PTE_PAT1: u64 = 1 << 61;
/// LRU-bypass — page never ages.
pub const PTE_LRU_BYPASS: u64 = 1 << 62;
/// NX — PPGTT no-execute.
pub const PTE_NX: u64 = 1 << 63;

/// PRM-mandated phys mask: bits[38:12]. Higher bits are reserved
/// — the GTT physical-address space is 39 bits wide.
pub const PTE_PHYS_MASK: u64 = 0x0000_007F_FFFF_F000;

/// Page size — every Gen12 GTT entry maps a 4 KiB page.
pub const GTT_PAGE_SIZE: u64 = 0x1000;

/// Documented PAT slots on Gen12. PRM Vol. 5 §"PAT Index Encoding".
///
/// The PAT (Page Attribute Table) is a 64-byte register block
/// programmed by firmware / BIOS at boot. Each slot picks a
/// (memory-type, cache-policy) combination; the GTT PTE selects
/// one of four slots through `PAT0` + `PAT1`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum PatSlot {
    /// Slot 0 — PAT default (typically Uncached).
    Slot0 = 0,
    /// Slot 1 — usually LLC + eLLC cached, write-back.
    Slot1 = 1,
    /// Slot 2 — write-combining (the typical scanout choice).
    Slot2 = 2,
    /// Slot 3 — extended (Xe-LPG only).
    Slot3 = 3,
}

impl PatSlot {
    /// Pack into the `PAT0` + `PAT1` PTE bits.
    pub const fn encode(self) -> u64 {
        let v = self as u64;
        ((v & 1) << 60) | (((v >> 1) & 1) << 61)
    }
    pub const fn decode(pte: u64) -> Self {
        let lo = (pte >> 60) & 1;
        let hi = (pte >> 61) & 1;
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
    /// Phys address has bits set outside the documented 39-bit
    /// physical-address space.
    PhysOutOfRange,
    /// Physical allocation failed.
    OutOfMemory,
    /// The requested GGTT range escapes the GGTT window implied
    /// by the actual GTTMMADR BAR length.
    OutOfBounds,
}

/// Build a present, read-only PTE for a scanout page.
///
/// `phys` must be 4 KiB-aligned and fit in 39 bits. `pat` picks
/// the cache policy — `Slot2` (write-combining) is the standard
/// choice for display-plane scanout.
pub fn encode_scanout_pte(phys: u64, pat: PatSlot) -> Result<u64, GttError> {
    if phys & 0xFFF != 0 {
        return Err(GttError::UnalignedPhys);
    }
    if phys & !PTE_PHYS_MASK != 0 {
        return Err(GttError::PhysOutOfRange);
    }
    Ok(PTE_PRESENT | (phys & PTE_PHYS_MASK) | pat.encode())
}

/// Build a present, read/write PTE for a 3D / compute engine
/// (PPGTT). `pat` typically `Slot1` (LLC cached) for shader
/// surfaces, `Slot2` for staging buffers.
pub fn encode_engine_pte(phys: u64, pat: PatSlot, executable: bool) -> Result<u64, GttError> {
    if phys & 0xFFF != 0 {
        return Err(GttError::UnalignedPhys);
    }
    if phys & !PTE_PHYS_MASK != 0 {
        return Err(GttError::PhysOutOfRange);
    }
    let mut v = PTE_PRESENT | PTE_RW | (phys & PTE_PHYS_MASK) | pat.encode();
    if !executable {
        v |= PTE_NX;
    }
    Ok(v)
}

/// Build a page-*table* entry pointing at the next-level table
/// at `next_level_phys`: the same 64-bit GFX PTE layout as a leaf
/// entry with only `PRESENT` set. Intermediate PPGTT entries
/// (PML4E / PDPTE / PDE) and GGTT entries share this encoding —
/// TGL PRM Vol. 5 §"GFX PTE Definition" defines one entry format
/// for every level of both walks.
pub fn encode_table_entry(next_level_phys: u64) -> Result<u64, GttError> {
    if next_level_phys & 0xFFF != 0 {
        return Err(GttError::UnalignedPhys);
    }
    if next_level_phys & !PTE_PHYS_MASK != 0 {
        return Err(GttError::PhysOutOfRange);
    }
    Ok(PTE_PRESENT | (next_level_phys & PTE_PHYS_MASK))
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
    let order = scanout_order_for(size_bytes).ok_or(GttError::OutOfMemory)?;
    let pages = size_bytes.div_ceil(GTT_PAGE_SIZE);
    check_ggtt_range(gtt_mmadr.len, gtt_offset, pages * GTT_PAGE_SIZE)?;
    let head = narf_memory::frame::alloc_pages_on(0, order).map_err(|_| GttError::OutOfMemory)?;
    let base = head.start_address().raw();
    for i in 0..pages {
        let phys = base + i * GTT_PAGE_SIZE;
        let pte = match encode_scanout_pte(phys, PatSlot::Slot2) {
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
        if PatSlot::decode(pte) != PatSlot::Slot2 {
            return TestResult::Fail("PAT slot lost in encode");
        }
        if pte & PTE_RW != 0 {
            return TestResult::Fail("scanout PTE must be RO");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_scanout_pte_layout);

    fn smoke_engine_pte_nx() -> TestResult {
        let pte = match encode_engine_pte(0x1000, PatSlot::Slot1, false) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        if pte & PTE_NX == 0 {
            return TestResult::Fail("non-executable engine PTE must set NX");
        }
        if pte & PTE_RW == 0 {
            return TestResult::Fail("engine PTE must be RW");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_engine_pte_nx);

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
        // Bit 39 set — outside the documented 39-bit phys window.
        match encode_scanout_pte(1u64 << 39, PatSlot::Slot2) {
            Err(GttError::PhysOutOfRange) => TestResult::Pass,
            _ => TestResult::Fail(">39-bit phys must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gtt",
        smoke_pte_rejects_out_of_range_phys
    );

    fn smoke_table_entry_encoding() -> TestResult {
        // Byte-for-byte pin: a table entry is PRESENT | phys, in
        // the same GFX PTE layout as a leaf (PRM Vol. 5).
        match encode_table_entry(0x0000_0001_2345_6000) {
            Ok(0x0000_0001_2345_6001) => {}
            _ => return TestResult::Fail("table entry must be phys | PRESENT"),
        }
        match encode_table_entry(0x1234) {
            Err(GttError::UnalignedPhys) => {}
            _ => return TestResult::Fail("unaligned table phys must be rejected"),
        }
        match encode_table_entry(1u64 << 39) {
            Err(GttError::PhysOutOfRange) => {}
            _ => return TestResult::Fail(">39-bit table phys must be rejected"),
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
