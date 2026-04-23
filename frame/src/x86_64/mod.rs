//! x86_64-specific bring-up.

core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("trap_entry.S"));

pub mod idt;
pub mod trap;

/// Install the IDT and bring the CPU into a state where exceptions route
/// through `rust_trap_handler` instead of triple-faulting. Called from
/// `_start_rust` before any code that might fault.
///
/// # Safety
/// Must run on the BSP, exactly once.
pub unsafe fn init_traps() {
    // SAFETY: IDT init owns its one-shot precondition.
    unsafe { idt::init() }
}
