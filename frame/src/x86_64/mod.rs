//! x86_64-specific bring-up.

core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("trap_entry.S"));

pub mod gdt;
pub mod idt;
pub mod percpu;
pub mod trap;

/// Install GDT (with TSS) and the IDT. After this returns, CPU exceptions
/// route through `rust_trap_handler`; NMI / #DF / #MC / #VC land on
/// dedicated IST stacks so stack-overflow recursion and re-fault
/// scenarios don't wedge the kernel.
///
/// # Safety
/// Must run on the BSP, exactly once.
pub unsafe fn init_traps() {
    // Order matters: GDT first because IDT entries name their code
    // selector (KCODE_SEL) and the TSS needs to be loaded before IST
    // slots are meaningful. Per-CPU GS setup depends on TSS.rsp0
    // being populated so it goes after gdt::init.
    // SAFETY: one-shot BSP invariant.
    unsafe {
        gdt::init();
        percpu::init_bsp();
        idt::init();
    }
}
