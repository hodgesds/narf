//! aarch64 MMU bring-up and identity mapping.

use crate::PhysAddr;

/// Errors from `init_mmu`.
#[derive(Copy, Clone, Debug)]
pub enum MmuError {
    FramesExhausted,
}

/// Higher-half kernel base: 0xFFFFFF8000000000.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFFFF8000000000;

/// # Safety
/// Must be called at EL1 (or higher) during early boot before paging is
/// reconfigured; reads `TTBR0_EL1`, which is only architecturally
/// accessible from EL1+.
pub unsafe fn init_mmu() -> Result<PhysAddr, MmuError> {
    let ttbr0: u64;
    // SAFETY: `mrs` reading `TTBR0_EL1` is a privileged but side-effect-free
    // read; the caller guarantees EL1+ (see `# Safety`), and `out(reg)` binds
    // a fresh local for the destination register.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("mrs {v}, ttbr0_el1", v = out(reg) ttbr0);
    }
    Ok(PhysAddr::new(ttbr0))
}
