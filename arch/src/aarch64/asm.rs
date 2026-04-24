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
/// Falls back to `spin_loop` on aarch64 today because the GICv3 +
/// generic-timer IRQ sources aren't wired yet — WFI without an IRQ
/// source wedges indefinitely. Once the aarch64 IRQ stack lands
/// (Stage 2 aarch64 polish), this becomes a real WFI.
#[inline(always)]
pub fn halt_until_irq() {
    // TODO(aarch64): replace with `wfi_once()` once generic-timer
    // IRQs via GICv3 are live. Today no IRQ source fires, so WFI
    // would hang.
    core::hint::spin_loop();
}
