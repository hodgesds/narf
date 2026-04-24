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

/// 128-bit atomic compare-and-swap via `CASP`.
///
/// # Safety
/// `ptr` must be 16-byte aligned and point to valid, writable memory.
/// This implementation requires ARMv8.1-LSE support.
#[inline(always)]
pub unsafe fn cas128(ptr: *mut u128, old: u128, new: u128) -> Result<u128, u128> {
    let old_low  = old as u64;
    let old_high = (old >> 64) as u64;
    let new_low  = new as u64;
    let new_high = (new >> 64) as u64;

    let res_low: u64;
    let res_high: u64;

    compiler_fence(Ordering::SeqCst);
    // SAFETY: CASP (with acquire-release semantics: CASPAL) is valid
    // on ARMv8.1+ CPUs. NARF's aarch64 baseline includes LSE.
    // ptr alignment is the caller's responsibility.
    // Rust's `asm!` disallows `name = inout("xN")` syntax — when a
    // register is explicit you reference it by register name directly
    // in the template. CASP needs specific pairs (x0+x1 for the old
    // value, x2+x3 for the new) so we bind those by position.
    // SAFETY: CASP (with acquire-release semantics: CASPAL) is valid
    // on ARMv8.1+ CPUs. NARF's aarch64 baseline includes LSE.
    // ptr alignment is the caller's responsibility.
    unsafe {
        asm!(
            "caspal x0, x1, x2, x3, [{ptr}]",
            inout("x0") old_low  => res_low,
            inout("x1") old_high => res_high,
            in("x2")    new_low,
            in("x3")    new_high,
            ptr = in(reg) ptr,
            options(nostack),
        );
    }
    compiler_fence(Ordering::SeqCst);

    let res = (res_low as u128) | ((res_high as u128) << 64);
    if res == old {
        Ok(res)
    } else {
        Err(res)
    }
}

/// Atomically replace a 4-byte instruction word at `addr` with `new`.
///
/// # Safety
/// Same contract as the x86_64 sibling. aarch64 instructions are
/// always 4 bytes + 4-byte aligned, so a single `str w, [x]` is the
/// whole instruction; the synchronisation dance below is what guarantees
/// the I-cache sees it before the next fetch (ARMv8 §B2.3).
#[inline(always)]
pub unsafe fn patch_word(addr: *mut u32, new: u32) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: aligned 4-byte store is atomic. Serialisation below.
    unsafe { core::ptr::write_volatile(addr, new); }
    // Self-modifying-code flush per ARMv8 B2.3:
    //   DSB ISH        — drain the pending data write to the PoU
    //   IC IVAU, <addr> — invalidate the I-cache line holding the patch
    //   DSB ISH        — ensure the invalidate completes before ISB
    //   ISB            — flush the pipeline so the next fetch sees the
    //                     new word
    unsafe {
        asm!(
            "dsb ish",
            "ic ivau, {a}",
            "dsb ish",
            "isb",
            a = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}
