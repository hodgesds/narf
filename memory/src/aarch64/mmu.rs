//! aarch64 MMU bring-up and identity mapping.

use crate::PhysAddr;

/// Errors from `init_mmu`.
#[derive(Copy, Clone, Debug)]
pub enum MmuError {
    FramesExhausted,
}

/// Higher-half kernel base: 0xFFFFFF8000000000.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFFFF8000000000;

/// Drop the boot identity map from `TTBR0_EL1`.
///
/// `boot.S` builds `l0_lo` with two 1 GiB blocks — `0x0` as Device (the
/// MMIO window) and `0x4000_0000` as Normal (RAM) — and leaves it in
/// `TTBR0_EL1`. Nothing replaces it except a user address space or a domain
/// root, so in kernel context with neither active, every physical address
/// below 2 GiB stays directly dereferenceable. That is the same hazard the
/// x86_64 side removed: a physical address and a kernel pointer become
/// interchangeable, and since both are `u64` the types cannot object.
///
/// RAM does not need it — `PhysAddr::kernel_ptr` ORs `KERNEL_PHYS_OFFSET`
/// and reaches RAM through TTBR1 — and MMIO belongs behind `ioremap`, which
/// maps Device memory explicitly rather than relying on a blanket block.
///
/// Zeroing `l0_lo[0]` rather than installing a fresh empty root keeps this
/// allocation-free and leaves the boot tables where a debugger expects them.
///
/// # Safety
/// Call only after `init_mmu` has installed the high-half tables and
/// `console::remap_to_virtual` has moved the UART off its identity base —
/// otherwise the first `writeln!` after this faults and takes the console
/// with it.
pub unsafe fn drop_boot_identity_map() {
    let ttbr0: u64;
    // SAFETY: privileged but side-effect-free read; we run at EL1.
    unsafe {
        core::arch::asm!("mrs {v}, ttbr0_el1", v = out(reg) ttbr0);
    }
    // TTBR0_EL1 carries the ASID in [63:48]; the table base is the rest.
    let root = PhysAddr::new(ttbr0 & 0x0000_FFFF_FFFF_F000);
    // SAFETY: the boot L0 table is reachable through the high-half window,
    // and entry 0 is the only populated slot `boot.S` wrote.
    unsafe {
        core::ptr::write_volatile(root.kernel_mut_ptr::<u64>(), 0);
    }
    // Full inner-shareable flush: the block descriptors this drops could be
    // cached on any CPU, and there is no single VA to invalidate.
    // SAFETY: TLB maintenance is always legal at EL1.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
}

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
    // Publish the physical-to-virtual offset for crates that sit below
    // narf-memory and so cannot call `PhysAddr::kernel_ptr` —
    // `narf-arch`, `narf-firmware`, `narf-initramfs`, `narf-fdt`. The
    // x86_64 side does this at the same point. Until now aarch64 never
    // did, so `narf_lib::directmap::pv` was the identity here and those
    // crates reached physical addresses through the boot identity window
    // instead: the DTB parse was the first thing to fault when it went.
    narf_lib::directmap::set_offset(crate::KERNEL_PHYS_OFFSET);
    Ok(PhysAddr::new(ttbr0))
}
