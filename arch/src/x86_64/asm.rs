//! Privileged-asm wrappers. Every entry point carries the
//! `compiler_fence(SeqCst)` pair from `arch/` §4 / `build/` §4 so fat LTO
//! cannot reorder loads/stores across the instruction boundary.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// Disable maskable interrupts via `CLI`.
#[inline(always)]
pub unsafe fn disable_interrupts() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `CLI` is always valid at CPL=0 and has no operand side effects
    // beyond IF=0. The fence pair keeps loads/stores from migrating across.
    unsafe { asm!("cli", options(nomem, nostack, preserves_flags)); }
    compiler_fence(Ordering::SeqCst);
}

/// Enable maskable interrupts via `STI`.
#[inline(always)]
pub unsafe fn enable_interrupts() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `STI` sets IF=1. Caller-side invariant: IDT is installed.
    unsafe { asm!("sti", options(nomem, nostack, preserves_flags)); }
    compiler_fence(Ordering::SeqCst);
}

/// Single `HLT`. Intended for use inside a loop; on its own an interrupt
/// (if enabled) will wake the CPU.
#[inline(always)]
pub unsafe fn halt_once() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `HLT` at CPL=0 halts until the next interrupt / SMI / NMI.
    unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)); }
    compiler_fence(Ordering::SeqCst);
}

/// Disable interrupts, then spin on `HLT` forever. Used for panic and Stage-1
/// end-of-boot before the async executor exists.
#[inline(always)]
pub fn halt_forever() -> ! {
    // SAFETY: leaving interrupts off and halting is always safe. We never
    // return, so the IRQ-state change has no observable effect on the rest
    // of the kernel.
    unsafe {
        disable_interrupts();
        loop { halt_once(); }
    }
}
