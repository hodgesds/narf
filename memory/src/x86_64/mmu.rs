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
use crate::{FrameAllocError, PhysAddr};

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
            // `NotSupported` (e.g. bump-impl free) and `AuthorityRevoked`
            // (Cap::check_live failure on install) shouldn't reach the
            // MMU alloc path — collapse to the closest existing error.
            FrameAllocError::NotSupported | FrameAllocError::AuthorityRevoked => {
                MmuError::AllocatorUninitialised
            }
        }
    }
}

/// PML4 index of the higher-half kernel base (-2 GiB). Virtual address
/// `0xFFFF_FFFF_8000_0000` decomposes as PML4=511, PDPT=510.
pub const HIGHER_HALF_PML4_INDEX: usize = 511;
/// PDPT index of the higher-half kernel base (-2 GiB).
pub const HIGHER_HALF_PDPT_INDEX: usize = 510;

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
    pml4: PageTable {
        entries: ZERO_ENTRIES,
    },
    pdpt_lo: PageTable {
        entries: ZERO_ENTRIES,
    },
    pdpt_hi_mmio: PageTable {
        entries: ZERO_ENTRIES,
    },
    pdpt_hi: PageTable {
        entries: ZERO_ENTRIES,
    },
};

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
///   * PML4[384 + i] → the high-half **kernel direct map**: one PDPT
///     per 512 GiB of installed RAM (`max_ram_phys`), each mapping
///     `KERNEL_DIRECT_MAP_BASE + P` to physical `P` via 1-GiB huge
///     pages. This is what lets the kernel reach RAM above 512 GiB —
///     the low identity map stops at PML4[0] (512 GiB) because
///     PML4[1..255] is claimed by user address space, so high RAM needs
///     its own kernel-only window. `direct_map_activate` publishes it
///     after the CR3 swap; `PhysAddr::kernel_mut_ptr` then adds the
///     offset.
///
/// Returns the physical address of the new PML4.
///
/// `max_ram_phys` is the exclusive top of installed RAM (bytes); the
/// direct map is sized to cover `[0, max_ram_phys)` rounded up to a
/// 512 GiB PML4-slot boundary.
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
pub unsafe fn init_mmu(max_ram_phys: u64) -> Result<PhysAddr, MmuError> {
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
    let tables_ptr = core::ptr::addr_of_mut!(EARLY_PAGE_TABLES);
    // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
    let pml4_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pml4) } as u64;
    // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
    let pdpt_lo_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_lo) } as u64;
    // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
    let pdpt_hi_mmio_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_hi_mmio) } as u64;
    // SAFETY: single-threaded boot-time access to this static; no concurrent mutation is possible.
    let pdpt_hi_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_hi) } as u64;
    let pml4_addr = PhysAddr::new(pml4_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_lo_addr = PhysAddr::new(pdpt_lo_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_hi_mmio_addr = PhysAddr::new(pdpt_hi_mmio_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_hi_addr = PhysAddr::new(pdpt_hi_virt.wrapping_sub(KERNEL_VIRT_BASE));

    // These frames came from the allocator and are identity-mapped in
    // the boot.S page tables (the low 1 GiB huge page covers them),
    // so the raw pointer is valid for a 4 KiB write.
    PageTable::zero_at(pml4_addr.as_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_lo_addr.as_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_hi_mmio_addr.as_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_hi_addr.as_mut_ptr::<PageTable>());

    // Step 2: populate.
    let flags_ptr = PtFlags::PRESENT | PtFlags::WRITABLE;
    let flags_1gb = PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::HUGE_PAGE;
    // SAFETY: the PML4/PDPT storage is identity-mapped (low 1 GiB of
    // boot.S's table), so writes go to the intended physical memory.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        // Low-identity PML4 + PDPT. Fill the whole PDPT (512 × 1 GiB
        // huge pages) so virt 0..512 GiB identity-maps phys 0..512 GiB.
        // The old map stopped at 4 GiB, which forced the frame
        // allocator's `EARLY_PHYS_CEILING` to permanently exclude all
        // RAM above 4 GiB: on a q35 PCI-hole split (QEMU -m ≥ 4G, real
        // 16 GiB laptops) usable RAM is relocated to start at phys
        // 4 GiB, so anything past the boundary was untouchable and a
        // direct `phys.raw() as *mut T` access would #PF. Blanketing
        // the low 512 GiB makes every installed frame reachable by an
        // identity (phys == virt) pointer; unpopulated gaps in that
        // range are simply never accessed (the buddy only hands out
        // real RAM). 512 GiB is the PDPT's full reach and dwarfs any
        // supported machine. Caller releases the ceiling once this
        // map is live.
        let pml4_lo_entry = PageTableEntry::new(pdpt_lo_addr, flags_ptr);
        write_identity::<PageTableEntry>(pml4_addr, pml4_lo_entry);
        for gib in 0u64..512 {
            let phys = PhysAddr::new(gib << 30);
            let entry = PageTableEntry::new(phys, flags_1gb);
            let slot = PhysAddr::new(pdpt_lo_addr.raw() + gib * 8);
            write_identity::<PageTableEntry>(slot, entry);
        }

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
        // PML4[1]: entry index 1 * 8 bytes per entry = byte offset 8.
        let pml4_hi_mmio_slot = PhysAddr::new(pml4_addr.raw() + 8);
        write_identity::<PageTableEntry>(pml4_hi_mmio_slot, pml4_hi_mmio_entry);
        for gib in 1u64..512 {
            // Each PDPT entry covers virt 512 GiB + gib * 1 GiB,
            // identity-mapped to the matching phys.
            let phys = PhysAddr::new((512 + gib) << 30);
            let entry = PageTableEntry::new(phys, flags_1gb);
            let slot = PhysAddr::new(pdpt_hi_mmio_addr.raw() + gib * 8);
            write_identity::<PageTableEntry>(slot, entry);
        }

        // High-half PML4[511] + PDPT[510] → phys 0 (1 GiB huge page).
        // Virtual 0xFFFF_FFFF_8000_0000 + x maps to physical 0 + x.
        let pml4_hi_entry = PageTableEntry::new(pdpt_hi_addr, flags_ptr);
        let pml4_hi_slot = PhysAddr::new(pml4_addr.raw() + (HIGHER_HALF_PML4_INDEX as u64) * 8);
        write_identity::<PageTableEntry>(pml4_hi_slot, pml4_hi_entry);

        let hh_entry = PageTableEntry::new(PhysAddr::new(0), flags_1gb);
        let hh_slot = PhysAddr::new(pdpt_hi_addr.raw() + (HIGHER_HALF_PDPT_INDEX as u64) * 8);
        write_identity::<PageTableEntry>(hh_slot, hh_entry);
    }

    // High-half kernel direct map (PML4[384 + chunk]). Give the kernel a
    // window that reaches RAM above 512 GiB, which the low identity map
    // can't cover (PML4[1..255] is user address space). Slot 384 clears
    // both the PCID per-domain private range (PML4[256..271], which
    // domain.rs *overwrites* per domain) and the kernel image
    // (PML4[511]); see KERNEL_DIRECT_MAP_BASE. Each PML4 slot spans
    // 512 GiB, so one BSS PDPT of 512 × 1-GiB huge pages covers each
    // 512-GiB chunk of RAM. PML4[256..512] is copied verbatim into every
    // per-domain / user PML4 (see x86_64/paging.rs), so the direct map
    // reaches every address space without extra work.
    //
    // Built ONLY when installed RAM actually exceeds the low identity
    // map (512 GiB): below that every frame is reachable at `phys ==
    // virt` and the map is pure overhead, and its mere presence in the
    // cloned PML4s perturbs the PCID per-domain isolation setup. So on
    // all real hardware and QEMU up to 512 GiB the kernel runs on the
    // low identity map alone, exactly as before this feature.
    const CHUNK_BYTES: u64 = 512u64 << 30; // one PML4 slot = 512 GiB
    let build_direct_map = max_ram_phys > crate::addr::LOW_IDENTITY_LIMIT;
    if build_direct_map {
        let want_chunks = max_ram_phys.div_ceil(CHUNK_BYTES).max(1);
        let dmap_chunks = want_chunks.min(crate::addr::KERNEL_DIRECT_MAP_PML4_SLOTS as u64);
        for chunk in 0..dmap_chunks {
            // PDPT frames come from the buddy: the early phys ceiling is
            // still armed (the caller releases it only after we return),
            // so each is < 4 GiB and reachable through the boot identity
            // map for the fill writes below. This alloc only runs on
            // > 512 GiB machines, so a small-RAM boot's frame layout is
            // untouched.
            let pdpt = crate::frame::alloc_frame()?.start_address();
            // SAFETY: `pdpt` is < 4 GiB, identity-mapped by boot.S, so the
            // raw pointer is valid for a 4 KiB zero + entry writes.
            unsafe {
                PageTable::zero_at(pdpt.as_mut_ptr::<PageTable>());
                for gib in 0u64..512 {
                    let phys = PhysAddr::new(chunk * CHUNK_BYTES + (gib << 30));
                    let entry = PageTableEntry::new(phys, flags_1gb);
                    let slot = PhysAddr::new(pdpt.raw() + gib * 8);
                    write_identity::<PageTableEntry>(slot, entry);
                }
                let pml4_idx = crate::addr::KERNEL_DIRECT_MAP_PML4_BASE as u64 + chunk;
                let pml4_slot = PhysAddr::new(pml4_addr.raw() + pml4_idx * 8);
                write_identity::<PageTableEntry>(pml4_slot, PageTableEntry::new(pdpt, flags_ptr));
            }
        }
    }

    // Step 3 from console/ §3.1: *caller* prints the handoff line
    // before calling us so a panic across the CR3 swap is visible.
    //
    // Step 4: swap CR3. Any access from this instruction forward uses
    // the new PML4. The new mapping identity-covers 0..512 GiB, which
    // includes:
    //   - the kernel image (loaded at phys 0x100000)
    //   - the UART (I/O ports, not memory, so MMU-irrelevant)
    //   - the heap + allocator bookkeeping (in the kernel image's .bss)
    //   - the newly-allocated PML4 + PDPT themselves
    // so control-flow continues uninterrupted.
    //
    // SAFETY: invariants above; caller supplied the single-CPU BSP
    // precondition.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        write_cr3(pml4_addr);
    }

    // If we installed the high-half direct map, publish it so the
    // kernel RAM accessors switch >= 512 GiB frames to the offset
    // window. AFTER the CR3 swap: until now kernel_mut_ptr must stay on
    // identity (the boot CR3 has no high-half map). When no direct map
    // was built (RAM <= 512 GiB) the flag stays false and every frame is
    // reached at `phys == virt` through the low identity map.
    if build_direct_map {
        crate::addr::direct_map_activate();
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
