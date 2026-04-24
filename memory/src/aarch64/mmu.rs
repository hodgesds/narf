//! aarch64 MMU bring-up and identity mapping.

use crate::aarch64::paging::{PageTable, PageTableEntry, PtFlags, write_identity};
use crate::{alloc_frame, PhysAddr};
use narf_arch::aarch64::sysreg;

/// Errors from `init_mmu`.
#[derive(Copy, Clone, Debug)]
pub enum MmuError {
    FramesExhausted,
}

pub const MAIR_VALUE: u64 = 0x0000_0000_0004_F0FF;

/// Higher-half kernel base: 0xFFFFFFFF80000000.
/// This corresponds to TTBR1_EL1 and L1 index 510 (39-bit VA).
pub const KERNEL_VIRT_BASE: u64 = 0xFFFFFFFF80000000;

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
        // TTBR0 (Identity)
        write_identity(l1_lo_addr, PageTableEntry::new(PhysAddr::new(0), flags_dev));
        write_identity(PhysAddr::new(l1_lo_addr.raw() + 8), PageTableEntry::new(PhysAddr::new(0x4000_0000), flags_ram));

        // TTBR1 (Higher-half @ -2 GiB)
        // Index 510 maps RAM base 0x4000_0000.
        let l1_hi_slot = PhysAddr::new(l1_hi_addr.raw() + 510 * 8);
        write_identity(l1_hi_slot, PageTableEntry::new(PhysAddr::new(0x4000_0000), flags_ram));
    }

    unsafe {
        sysreg::write_mair_el1(MAIR_VALUE);
        sysreg::isb();

        let tcr: u64 = (25 << 0)  | (25 << 16) |
                       (3 << 12)  | (3 << 28)  |
                       (1 << 10)  | (1 << 26)  |
                       (1 << 8)   | (1 << 24)  |
                       (2 << 30)  | (2u64 << 32);
        sysreg::write_tcr_el1(tcr);
        sysreg::isb();

        sysreg::write_ttbr0_el1(l1_lo_addr.raw());
        sysreg::write_ttbr1_el1(l1_hi_addr.raw());
        sysreg::isb();
        
        let mut sctlr = sysreg::read_sctlr_el1();
        sctlr |= 0x1 | 0x4 | 0x1000 | (1u64 << 43);
        sysreg::write_sctlr_el1(sctlr);
        
        sysreg::tlb_flush_all();
    }

    Ok(l1_lo_addr)
}
