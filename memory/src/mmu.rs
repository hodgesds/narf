//! MMU bring-up and the `console/` §3.1 handoff protocol.
//!
//! Stage 1 scope: build our own identity-mapped PML4 covering the
//! first 4 GiB with 1-GiB huge pages, execute the handoff sequence in
//! `console/` §3.1, and swap to it. Higher-half migration (`-2 GiB`
//! kernel) is a Wave 2 follow-on.
//!
//! The handoff sequence, verbatim from `console/` §3.1:
//!
//!   1. Build final page tables (including identity + kernel-virtual
//!      for the UART region).
//!   2. Call `console::write_str("mmu: handoff...\n")` via the current
//!      phys base — guaranteed visible.
//!   3. Execute MMU enable / CR3 load, then immediately call
//!      `console::remap_to_virtual(VIRT)`.
//!   4. Tear down identity mapping for the UART (kernel-virtual
//!      mapping is now sole).
//!
//! Stage 1 keeps the UART identity-mapped (no higher-half), so step
//! 4 is a no-op — the protocol still runs so future callers don't
//! have to retrofit the sequence.

#![cfg(target_arch = "x86_64")]

use crate::paging::{PageTable, PageTableEntry, PtFlags, write_cr3, write_identity};
use crate::{alloc_frame, FrameAllocError, PhysAddr};

/// Errors from `init_mmu`. Stage-1 failure modes are limited to
/// frame exhaustion and alloc-before-init.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MmuError {
    FramesExhausted,
    AllocatorUninitialised,
}

impl From<FrameAllocError> for MmuError {
    fn from(e: FrameAllocError) -> Self {
        match e {
            FrameAllocError::Exhausted    => MmuError::FramesExhausted,
            FrameAllocError::Uninitialised => MmuError::AllocatorUninitialised,
        }
    }
}

/// Build a fresh identity-mapped PML4 covering the first 4 GiB with
/// 1-GiB huge pages and swap CR3 to it. Returns the physical address
/// of the new PML4.
///
/// This function is the *memory/* half of the `console/` §3.1
/// handoff protocol; the caller (`frame/main.rs`) is responsible for
/// the `mmu: handoff...` print immediately before and the
/// `console::remap_to_virtual(...)` call immediately after — memory/
/// can't depend on narf-console without introducing a crate cycle
/// (narf-console → narf-memory already).
///
/// # Safety
/// - Must be called once, on the BSP, with interrupts disabled and no
///   concurrent MMU activity.
/// - `memory::init_from_map` must have populated the frame allocator.
/// - Every address range the kernel will access after this call must
///   be covered by the identity map being built (low 4 GiB is fine for
///   Stage 1; Wave 2 higher-half map adds kernel-virtual coverage).
pub unsafe fn init_mmu() -> Result<PhysAddr, MmuError> {
    // Step 1: allocate and zero a PML4 + PDPT.
    let pml4_frame = alloc_frame()?;
    let pdpt_frame = alloc_frame()?;
    let pml4_addr  = pml4_frame.start_address();
    let pdpt_addr  = pdpt_frame.start_address();

    // These frames came from the allocator and are identity-mapped in
    // the boot.S page tables (the low 1 GiB huge page covers them),
    // so the raw pointer is valid for a 4 KiB write.
    PageTable::zero_at(pml4_addr.as_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_addr.as_mut_ptr::<PageTable>());

    // Step 2: populate.
    //
    // PML4[0] → PDPT (P | RW)
    // PDPT[0..=3] = identity 1-GiB huge pages at phys 0, 1 GiB, 2 GiB, 3 GiB.
    //   Covers the first 4 GiB of physical address space — plenty for
    //   Stage 1's kernel-in-low-4-GiB layout. 4 × 1-GiB huge pages is
    //   4 entries, each setting HUGE_PAGE | WRITABLE | PRESENT.
    let flags_ptr = PtFlags::PRESENT | PtFlags::WRITABLE;
    let flags_1gb = PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::HUGE_PAGE;
    // SAFETY: the PML4/PDPT storage is identity-mapped (low 1 GiB of
    // boot.S's table), so writes go to the intended physical memory.
    unsafe {
        let pml4_entry = PageTableEntry::new(pdpt_addr, flags_ptr);
        write_identity::<PageTableEntry>(pml4_addr, pml4_entry);

        for gib in 0u64..=3 {
            let phys  = PhysAddr::new(gib << 30);
            let entry = PageTableEntry::new(phys, flags_1gb);
            let slot  = PhysAddr::new(pdpt_addr.raw() + gib * 8);
            write_identity::<PageTableEntry>(slot, entry);
        }
    }

    // Step 3 from console/ §3.1: *caller* prints the handoff line
    // before calling us so a panic across the CR3 swap is visible.
    //
    // Step 4: swap CR3. Any access from this instruction forward uses
    // the new PML4. The new mapping identity-covers 0..=4 GiB, which
    // includes:
    //   - the kernel image (loaded at phys 0x100000)
    //   - the UART (I/O ports, not memory, so MMU-irrelevant)
    //   - the heap + allocator bookkeeping (in the kernel image's .bss)
    //   - the newly-allocated PML4 + PDPT themselves
    // so control-flow continues uninterrupted.
    //
    // SAFETY: invariants above; caller supplied the single-CPU BSP
    // precondition.
    unsafe { write_cr3(pml4_addr); }

    // Step 5: *caller* notifies the console with a post-switch
    // `remap_to_virtual(virt)`.
    //
    // Step 6 from console/ §3.1 is "tear down the identity map for
    // UART now that the kernel-virtual mapping is sole." At Stage 1
    // there *is* no separate kernel-virtual mapping, so this step is
    // intentionally a no-op. Wave 2 higher-half migration adds the
    // kernel-virtual map and the tear-down.

    Ok(pml4_addr)
}
