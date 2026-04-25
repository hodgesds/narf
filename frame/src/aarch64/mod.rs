//! aarch64-specific bring-up. `boot.S` holds the EL1 entry and stack
//! setup; it then calls `_start_rust(magic, payload)` with magic set to
//! the DTB magic (0xd00dfeed) and payload set to X0 (the DTB phys addr).
//!
//! `vec.S` holds the EL1 exception vector table and the 5 Rust-facing
//! dispatch stubs (irq / sync_spx / sync_sp0 / serror / unimpl).

core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("vec.S"));

pub mod trap;
pub mod user;

extern "C" {
    /// Linker symbol for the EL1 vector table base (from `vec.S`).
    static __narf_vector_table: u8;
}

/// Install the EL1 vector table by writing VBAR_EL1. After this call,
/// synchronous exceptions, IRQs, FIQs, and SErrors route through
/// `vec.S`'s handlers instead of whatever state the bootloader left.
///
/// # Safety
/// Must be called exactly once, on the BSP, at EL1, with IRQs masked.
pub unsafe fn init_traps() {
    let vbar = core::ptr::addr_of!(__narf_vector_table) as u64;
    // SAFETY: address is the linker-provided vector-table base; 2 KiB
    // aligned by the asm's `.align 11`.
    unsafe { narf_arch::aarch64::sysreg::write_vbar_el1(vbar); }
}
