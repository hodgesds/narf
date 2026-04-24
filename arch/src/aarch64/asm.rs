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

/// Read DAIF — the A/I/F/D interrupt-mask flags (bits 6-9).
#[inline(always)]
pub fn read_daif() -> u64 {
    let v: u64;
    // SAFETY: MRS DAIF is always legal at EL1.
    unsafe {
        core::arch::asm!("mrs {v}, daif", v = out(reg) v,
                         options(nomem, nostack, preserves_flags));
    }
    v
}

/// True iff IRQs are currently enabled (DAIF.I == 0, bit 7 clear).
#[inline(always)]
pub fn interrupts_enabled() -> bool {
    read_daif() & (1 << 7) == 0
}

/// Wait for an interrupt.
///
/// Uses WFI only when IRQs are unmasked AND a wake source is live
/// (the generic-timer PPI, enabled by `interrupts/aarch64/timer.rs`).
/// If IRQs are masked (e.g. during the kernel-test harness which
/// runs synchronously without starting the timer), falls back to
/// `spin_loop` — WFI with no IRQ source would hang forever.
#[inline(always)]
pub fn halt_until_irq() {
    if interrupts_enabled() {
        // SAFETY: WFI at EL1 is always safe; it stalls the CPU until
        // a wake condition. With DAIF.I=0 and the GIC delivering the
        // generic-timer PPI, the wake fires on each IRQ.
        unsafe { wfi_once(); }
    } else {
        core::hint::spin_loop();
    }
}
