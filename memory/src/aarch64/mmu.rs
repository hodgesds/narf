//! aarch64 MMU bring-up and identity mapping.

use crate::aarch64::paging::{PageTable, PageTableEntry, PtFlags, write_identity};
use crate::{alloc_frame, PhysAddr};
use narf_arch::aarch64::sysreg;

/// Errors from `init_mmu`.
#[derive(Copy, Clone, Debug)]
pub enum MmuError {
    FramesExhausted,
}

/// MAIR_EL1 configuration:
///   Attr 0: Normal, Inner/Outer Write-Back Non-transient (0xFF)
///   Attr 1: Normal Tagged, Inner/Outer Write-Back Non-transient (0xF0)
///   Attr 2: Device-nGnRE (0x04)
pub const MAIR_VALUE: u64 = 0x0000_0000_0004_F0FF;

/// Higher-half kernel base: 0xFFFFFF8000000000.
/// This corresponds to TTBR1_EL1 and L1 index 0 (39-bit VA).
pub const KERNEL_VIRT_BASE: u64 = 0xFFFFFF8000000000;

/// Build page tables covering:
///   - TTBR0: first 2 GiB identity-mapped.
///   - TTBR1: first 2 GiB mapped to 0xFFFFFF8000000000.
pub unsafe fn init_mmu() -> Result<PhysAddr, MmuError> {
    let l1_lo_frame = alloc_frame().map_err(|_| MmuError::FramesExhausted)?;
    let l1_hi_frame = alloc_frame().map_err(|_| MmuError::FramesExhausted)?;
    
    let l1_lo_addr = l1_lo_frame.start_address();
    let l1_hi_addr = l1_hi_frame.start_address();

    PageTable::zero_at(l1_lo_addr.as_mut_ptr::<PageTable>());
    PageTable::zero_at(l1_hi_addr.as_mut_ptr::<PageTable>());

    let flags_dev = PtFlags::VALID | PtFlags::AF | PtFlags::SH_INNER | PtFlags::ATTR_DEVICE;
    let flags_ram = PtFlags::VALID | PtFlags::AF | PtFlags::SH_INNER | PtFlags::ATTR_TAGGED;
    
    unsafe {
        // --- TTBR0 (Identity) ---
        // L1[0] -> 0x0000_0000 (1 GiB block for Devices)
        let l1_dev = PageTableEntry::new(PhysAddr::new(0), flags_dev);
        write_identity(l1_lo_addr, l1_dev);

        // L1[1] -> 0x4000_0000 (1 GiB block for RAM)
        let l1_ram = PageTableEntry::new(PhysAddr::new(0x4000_0000), flags_ram);
        let l1_ram_slot = PhysAddr::new(l1_lo_addr.raw() + 8);
        write_identity(l1_ram_slot, l1_ram);

        // --- TTBR1 (Higher-half) ---
        // L1[0] -> 0x0000_0000 (1 GiB block for Devices)
        write_identity(l1_hi_addr, l1_dev);
        // L1[1] -> 0x4000_0000 (1 GiB block for RAM)
        write_identity(PhysAddr::new(l1_hi_addr.raw() + 8), l1_ram);
    }

    // Configure MMU.
    unsafe {
        sysreg::write_mair_el1(MAIR_VALUE);
        sysreg::isb();

        // TCR_EL1: 
        //   T0SZ=25, T1SZ=25 (39-bit VAs for both halves)
        //   TG0=0, TG1=2 (4KB granules for both)
        //   SH0=3, SH1=3 (Inner Shareable)
        //   ORGN0=1, ORGN1=1, IRGN0=1, IRGN1=1 (WB/WA)
        //   TBI0=1, TBI1=1 (MTE support)
        //   IPS=2 (40-bit IPA)
        let tcr: u64 = (25 << 0)  | (25 << 16) |  // T0SZ, T1SZ
                       (0 << 14)  | (2 << 30)  |  // TG0, TG1
                       (3 << 12)  | (3 << 28)  |  // SH0, SH1
                       (1 << 10)  | (1 << 26)  |  // ORGN0, ORGN1
                       (1 << 8)   | (1 << 24)  |  // IRGN0, IRGN1
                       (1u64 << 37) | (1u64 << 38) | // TBI0, TBI1
                       (2u64 << 32);              // IPS
        sysreg::write_tcr_el1(tcr);
        sysreg::isb();

        sysreg::write_ttbr0_el1(l1_lo_addr.raw());
        sysreg::write_ttbr1_el1(l1_hi_addr.raw());
        sysreg::isb();
        
        // SCTLR_EL1: M=1, C=1, I=1, ATA=1.
        let mut sctlr = sysreg::read_sctlr_el1();
        sctlr |= 0x1 | 0x4 | 0x1000 | (1u64 << 43);
        sysreg::write_sctlr_el1(sctlr);
        
        sysreg::tlb_flush_all();
    }

    Ok(l1_lo_addr)
}
