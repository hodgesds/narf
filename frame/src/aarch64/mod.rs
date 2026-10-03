//! aarch64-specific bring-up. `boot.S` holds the EL1 entry and stack
//! setup; it then calls `_start_rust(magic, payload, stack_lo, stack_hi)`
//! with magic set to the DTB magic (0xd00dfeed), payload set to X0 (the DTB
//! phys addr), and the boot stack's physical bounds.
//!
//! `vec.S` holds the EL1 exception vector table and the 5 Rust-facing
//! dispatch stubs (irq / sync_spx / sync_sp0 / serror / unimpl).

core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("vec.S"));
core::arch::global_asm!(include_str!("smp_entry.S"));

pub mod smp;
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
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::aarch64::sysreg::write_vbar_el1(vbar);
    }
}

/// Kernel exit code for a failed [`assert_on_boot_stack`].
///
/// Distinct from the 42 every aarch64 trap exit uses (`trap.rs`), so a run's
/// exit status alone tells "BSP booted on the wrong stack" from "synchronous
/// exception". aarch64 exits through semihosting and QEMU reports the kernel
/// code directly; xtask treats every status but 0 as failure, and 43 is not
/// the suite's 1 either.
pub const BOOT_STACK_CHECK_EXIT_CODE: u32 = 43;

/// Refuse to run the BSP anywhere but its own boot stack.
///
/// `lo_phys`/`hi_phys` are `stack_bottom`/`stack_top` as `boot.S` computed
/// them with `adrp` from the physical PC. SP itself came from the
/// `stack_top_virt` literal, which the KASLR apply pass rewrites whenever
/// `xtask`'s extractor classifies its value as moving with the image. The
/// linear map does not move, so a misclassified literal leaves SP a whole
/// slide (a nonzero multiple of 2 MiB, far past this 64 KiB stack) above the
/// linear alias of the real stack -- on kernel text or buddy-owned RAM that
/// the stack and its other owner then corrupt at random, surfacing much later
/// as unrelated crashes. Comparing against a derivation no relocation touches
/// turns that into one deterministic failure, before the heap exists.
///
/// Exits, as the trap path does, rather than panicking: `panic_sink` halts
/// forever, which a test harness can only see as its own timeout. The code is
/// [`BOOT_STACK_CHECK_EXIT_CODE`], not the trap path's 42.
pub fn assert_on_boot_stack(lo_phys: u64, hi_phys: u64) {
    use core::fmt::Write as _;
    let sp: u64;
    // SAFETY: reading SP has no side effects.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    let lo = narf_memory::PhysAddr::new(lo_phys).kernel_ptr::<u8>() as u64;
    let hi = narf_memory::PhysAddr::new(hi_phys).kernel_ptr::<u8>() as u64;
    if (lo..=hi).contains(&sp) {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "\n*** BOOT STACK CHECK FAILED ***\n  \
         BSP is not on its boot stack: sp={sp:#x}, boot stack is [{lo:#x}, {hi:#x}] \
         (linear alias of phys [{lo_phys:#x}, {hi_phys:#x}]); \
         was the stack_top_virt literal slid by KASLR?"
    );
    // SAFETY: exit is our fail path, as in `trap::rust_aarch64_sync`.
    unsafe { narf_arch::exit_kernel(BOOT_STACK_CHECK_EXIT_CODE) }
}
