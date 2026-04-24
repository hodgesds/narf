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

/// Build a fresh 3-level page table covering the first 2 GiB identity-mapped.
pub unsafe fn init_mmu() -> Result<PhysAddr, MmuError> {
    // For 3-level (39-bit VA), TTBR0 points at an L1 table.
    let l1_frame = alloc_frame().map_err(|_| MmuError::FramesExhausted)?;
    let l1_addr = l1_frame.start_address();

    PageTable::zero_at(l1_addr.as_mut_ptr::<PageTable>());

    let flags_dev = PtFlags::VALID | PtFlags::AF | PtFlags::SH_INNER | PtFlags::ATTR_DEVICE;
    let flags_ram = PtFlags::VALID | PtFlags::AF | PtFlags::SH_INNER | PtFlags::ATTR_TAGGED;
    
    unsafe {
        // L1[0] -> 0x0000_0000 (1 GiB block for Devices)
        let l1_dev = PageTableEntry::new(PhysAddr::new(0), flags_dev);
        write_identity(l1_addr, l1_dev);

        // L1[1] -> 0x4000_0000 (1 GiB block for RAM)
        let l1_ram = PageTableEntry::new(PhysAddr::new(0x4000_0000), flags_ram);
        let l1_ram_slot = PhysAddr::new(l1_addr.raw() + 8);
        write_identity(l1_ram_slot, l1_ram);
    }

    // Configure MMU.
    unsafe {
        sysreg::write_mair_el1(MAIR_VALUE);
        sysreg::isb();

        // TCR_EL1: T0SZ=25 (39-bit), TG0=4KB, SH0=Inner, WB/WA, TBI0=1, IPS=40-bit.
        let tcr: u64 = (25 << 0) | (3 << 12) | (1 << 10) | (1 << 8) | (1u64 << 37) | (2u64 << 32);
        sysreg::write_tcr_el1(tcr);
        sysreg::isb();

        sysreg::write_ttbr0_el1(l1_addr.raw());
        sysreg::isb();
        
        // SCTLR_EL1:
        //   M=1, C=1, I=1
        //   TCF=00 (Tag Check Faults disabled for now to avoid hang on uninitialized tags)
        //   ATA=1 (Allocation Tag Access allowed)
        let mut sctlr = sysreg::read_sctlr_el1();
        sctlr |= 0x1 | 0x4 | 0x1000 | (1u64 << 43);
        sysreg::write_sctlr_el1(sctlr);
        
        sysreg::tlb_flush_all();
    }

    Ok(l1_addr)
}
