//! aarch64 MMU bring-up and identity mapping.

use crate::{PhysAddr};

/// Errors from `init_mmu`.
#[derive(Copy, Clone, Debug)]
pub enum MmuError {
    FramesExhausted,
}

/// Higher-half kernel base: 0xFFFFFF8000000000.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFFFF8000000000;

pub unsafe fn init_mmu() -> Result<PhysAddr, MmuError> {
    let ttbr0: u64;
    unsafe {
        core::arch::asm!("mrs {v}, ttbr0_el1", v = out(reg) ttbr0);
    }
    Ok(PhysAddr::new(ttbr0))
}
