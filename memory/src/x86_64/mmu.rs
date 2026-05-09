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

use crate::paging::{write_cr3, write_identity, PageTable, PageTableEntry, PtFlags};
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
            FrameAllocError::Exhausted => MmuError::FramesExhausted,
            FrameAllocError::Uninitialised => MmuError::AllocatorUninitialised,
        }
    }
}

/// PML4 index of the higher-half kernel base (-2 GiB). Virtual address
/// `0xFFFF_FFFF_8000_0000` decomposes as PML4=511, PDPT=510.
pub const HIGHER_HALF_PML4_INDEX: usize = 511;
/// PDPT index of the higher-half kernel base (-2 GiB).
pub const HIGHER_HALF_PDPT_INDEX: usize = 510;

/// Build a fresh PML4 with:
///   * PML4[0] → PDPT covering the first 4 GiB identity-mapped via
///     four 1-GiB huge pages. Keeps low-half addresses live for
///     Stage-2-era kernel code that's still linked at low physical.
///   * PML4[511] → a second PDPT with a 1-GiB huge page at PDPT[510]
///     mapping `0xFFFF_FFFF_8000_0000..0xFFFF_FFFF_C000_0000` to
///     physical `0x0..0x4000_0000`. This is the higher-half window a
///     future linker script will place `.text/.rodata/.data/.bss`
///     into — the same physical pages become reachable at both low
///     and high virtual addresses.
///
/// Returns the physical address of the new PML4.
///
/// This function is the *memory/* half of the `console/` §3.1
/// handoff protocol; the caller (`frame/main.rs`) is responsible for
/// the `mmu: handoff...` print immediately before and the
/// `console::remap_to_virtual(...)` call immediately after.
///
/// # Safety
/// - Must be called once, on the BSP, with interrupts disabled and no
///   concurrent MMU activity.
/// - `memory::init_from_map` must have populated the frame allocator.
/// - Every address range the kernel will access after this call must
///   be covered by the identity map being built (currently the low
///   4 GiB + the high-half -2 GiB window).
/// Static-BSS storage for the four early page tables.
///
/// The frame allocator can return frames anywhere in usable RAM,
/// including above 4 GiB on machines where QEMU/UEFI splits RAM
/// around the PCI hole (q35 with -m ≥ 4G puts ~1 GiB of RAM at
/// 0x100000000+; real Zen2 laptops with 16 GiB do the same).
/// The boot.S identity map only covers 0..4 GiB, so a
/// high-frame return would page-fault on the first
/// `zero_at`/`write_identity` call.
///
/// Putting the tables in BSS guarantees they live within the
/// kernel image's load region (0x1000000+, well under 4 GiB)
/// and are therefore always reachable. Each `PageTable` is
/// `#[repr(C, align(4096))]` so the BSS layout is correct
/// for direct CR3 use.
#[repr(C, align(4096))]
struct EarlyPageTables {
    pml4: PageTable,
    pdpt_lo: PageTable,
    pdpt_hi_mmio: PageTable,
    pdpt_hi: PageTable,
}

const ZERO_ENTRIES: [PageTableEntry; 512] = [PageTableEntry::EMPTY; 512];
static mut EARLY_PAGE_TABLES: EarlyPageTables = EarlyPageTables {
    pml4: PageTable { entries: ZERO_ENTRIES },
    pdpt_lo: PageTable { entries: ZERO_ENTRIES },
    pdpt_hi_mmio: PageTable { entries: ZERO_ENTRIES },
    pdpt_hi: PageTable { entries: ZERO_ENTRIES },
};

pub unsafe fn init_mmu() -> Result<PhysAddr, MmuError> {
    use crate::beacon;
    // Use BSS-resident page tables (see `EarlyPageTables` doc) so
    // the four storage buffers are guaranteed to be in the
    // boot.S 4-GiB identity-mapped window. Asking the frame
    // allocator could return a frame above 4 GiB on machines
    // with the PCI-hole RAM split, which would fault on the
    // first write.
    //
    // The address-of yields a HIGH-HALF VIRTUAL address (kernel
    // is linked at `KERNEL_VIRT_BASE = 0xFFFFFFFF80000000`).
    // CR3 + PageTableEntry::new both want PHYSICAL addresses, so
    // subtract the kernel virt base to convert. The boot.S
    // higher-half mapping makes `phys = virt - 0xFFFFFFFF80000000`
    // exact for kernel-image symbols.
    //
    // SAFETY: single-threaded boot path; this is the only writer
    // to `EARLY_PAGE_TABLES`.
    const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
    let tables_ptr = unsafe { core::ptr::addr_of_mut!(EARLY_PAGE_TABLES) };
    let pml4_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pml4) } as u64;
    let pdpt_lo_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_lo) } as u64;
    let pdpt_hi_mmio_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_hi_mmio) } as u64;
    let pdpt_hi_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_hi) } as u64;
    let pml4_addr = PhysAddr::new(pml4_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_lo_addr = PhysAddr::new(pdpt_lo_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_hi_mmio_addr = PhysAddr::new(pdpt_hi_mmio_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_hi_addr = PhysAddr::new(pdpt_hi_virt.wrapping_sub(KERNEL_VIRT_BASE));
    beacon::paint(10, 0x0080_FFFF); // dim cyan: page-table addresses fixed

    // These frames came from the allocator and are identity-mapped in
    // the boot.S page tables (the low 1 GiB huge page covers them),
    // so the raw pointer is valid for a 4 KiB write.
    PageTable::zero_at(pml4_addr.as_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_lo_addr.as_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_hi_mmio_addr.as_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_hi_addr.as_mut_ptr::<PageTable>());
    beacon::paint(11, 0x0080_FF80); // dim lime: zero_at done

    // Step 2: populate.
    let flags_ptr = PtFlags::PRESENT | PtFlags::WRITABLE;
    let flags_1gb = PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::HUGE_PAGE;
    // SAFETY: the PML4/PDPT storage is identity-mapped (low 1 GiB of
    // boot.S's table), so writes go to the intended physical memory.
    unsafe {
        // Low-identity PML4 + PDPT (first 4 GiB).
        let pml4_lo_entry = PageTableEntry::new(pdpt_lo_addr, flags_ptr);
        write_identity::<PageTableEntry>(pml4_addr, pml4_lo_entry);
        for gib in 0u64..=3 {
            let phys = PhysAddr::new(gib << 30);
            let entry = PageTableEntry::new(phys, flags_1gb);
            let slot = PhysAddr::new(pdpt_lo_addr.raw() + gib * 8);
            write_identity::<PageTableEntry>(slot, entry);
        }
        beacon::paint(12, 0x00FF_FF80); // dim yellow: low identity done

        // High-MMIO identity (PML4[1]: virt 512 GiB ≤ V < 1 TiB →
        // phys 512 GiB ≤ P < 1 TiB). Covers UEFI-assigned 64-bit
        // BARs whose phys address sits above the low-4 GiB window.
        // OVMF on QEMU q35 places NVMe / virtio-PCI BARs around
        // phys 0xC0_0000_0000 (768 GiB); on real consumer hardware
        // the BARs typically sit between 0x80_0000_0000 and
        // 0xFE_0000_0000.
        //
        // PDPT[0] of this PML4 slot is reserved: user-mode binaries
        // (init / shell / testbin) link at virt
        // 0x0000_0080_0000_1000 which decodes to PML4[1] PDPT[0]
        // PD[0] PT[1]. Mapping PDPT[0] as a 1-GiB huge page would
        // collide with the user `materialize`'s 4-KiB descent.
        // Skipping it costs nothing — phys 512 GiB ≤ P < 513 GiB
        // is RAM territory in any sane laptop, never MMIO.
        let pml4_hi_mmio_entry = PageTableEntry::new(pdpt_hi_mmio_addr, flags_ptr);
        let pml4_hi_mmio_slot = PhysAddr::new(pml4_addr.raw() + 1 * 8);
        write_identity::<PageTableEntry>(pml4_hi_mmio_slot, pml4_hi_mmio_entry);
        for gib in 1u64..512 {
            // Each PDPT entry covers virt 512 GiB + gib * 1 GiB,
            // identity-mapped to the matching phys.
            let phys = PhysAddr::new((512 + gib) << 30);
            let entry = PageTableEntry::new(phys, flags_1gb);
            let slot = PhysAddr::new(pdpt_hi_mmio_addr.raw() + gib * 8);
            write_identity::<PageTableEntry>(slot, entry);
        }
        beacon::paint(13, 0x00FF_8080); // dim orange: hi-MMIO done

        // High-half PML4[511] + PDPT[510] → phys 0 (1 GiB huge page).
        // Virtual 0xFFFF_FFFF_8000_0000 + x maps to physical 0 + x.
        let pml4_hi_entry = PageTableEntry::new(pdpt_hi_addr, flags_ptr);
        let pml4_hi_slot = PhysAddr::new(pml4_addr.raw() + (HIGHER_HALF_PML4_INDEX as u64) * 8);
        write_identity::<PageTableEntry>(pml4_hi_slot, pml4_hi_entry);

        let hh_entry = PageTableEntry::new(PhysAddr::new(0), flags_1gb);
        let hh_slot = PhysAddr::new(pdpt_hi_addr.raw() + (HIGHER_HALF_PDPT_INDEX as u64) * 8);
        write_identity::<PageTableEntry>(hh_slot, hh_entry);
    }
    beacon::paint(14, 0x00FF_80FF); // dim magenta: higher-half done, about to CR3

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
    unsafe {
        write_cr3(pml4_addr);
    }

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
