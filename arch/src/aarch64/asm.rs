//! Privileged-asm wrappers for aarch64. See `arch/` §4 on the
//! `compiler_fence` discipline.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// Mask IRQs via `MSR DAIFSET, #0x2`.
#[inline(always)]
pub unsafe fn disable_interrupts() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: DAIFSET with I-bit (0x2) masks IRQs at EL1.
    unsafe { asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }
    compiler_fence(Ordering::SeqCst);
}

/// Unmask IRQs via `MSR DAIFCLR, #0x2`.
#[inline(always)]
pub unsafe fn enable_interrupts() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: DAIFCLR with I-bit (0x2) unmasks IRQs.
    unsafe { asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
    compiler_fence(Ordering::SeqCst);
}

/// `WFI` — wait for interrupt.
#[inline(always)]
pub unsafe fn wfi_once() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: WFI at EL1 stalls until the next IRQ or event.
    unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)); }
    compiler_fence(Ordering::SeqCst);
}

/// Mask IRQs and spin on `WFI` forever.
#[inline(always)]
pub fn halt_forever() -> ! {
    // SAFETY: masking and halting is always safe; we never return.
    unsafe {
        disable_interrupts();
        loop { wfi_once(); }
    }
}

/// Wait for an interrupt.
///
/// WFI wakes on any IRQ (including masked ones if `WFIT` semantics
/// apply), and the generic-timer PPI via GICv3 is now a live source
/// after `narf_interrupts::aarch64::init_bsp` + `start_timer` at boot.
#[inline(always)]
pub fn halt_until_irq() {
    // SAFETY: WFI at EL1 is always safe; it stalls the CPU until a
    // wake condition (IRQ / FIQ / SError / WFI-wake event).
    unsafe { wfi_once(); }
}
