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
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Enable maskable interrupts via `STI`.
#[inline(always)]
pub unsafe fn enable_interrupts() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `STI` sets IF=1. Caller-side invariant: IDT is installed.
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Single `HLT`. Intended for use inside a loop; on its own an interrupt
/// (if enabled) will wake the CPU.
#[inline(always)]
pub unsafe fn halt_once() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `HLT` at CPL=0 halts until the next interrupt / SMI / NMI.
    unsafe {
        asm!("hlt", options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read RFLAGS.
#[inline(always)]
pub fn read_rflags() -> u64 {
    let v: u64;
    // SAFETY: PUSHFQ/POP is always legal; reads current flags register.
    unsafe {
        asm!(
            "pushfq",
            "pop {v}",
            v = out(reg) v,
            options(preserves_flags),
        );
    }
    v
}

/// True iff IRQs are currently enabled (RFLAGS.IF == 1).
#[inline(always)]
pub fn interrupts_enabled() -> bool {
    read_rflags() & (1 << 9) != 0
}

/// Halt the CPU until the next interrupt, but only if IRQs are enabled
/// (otherwise HLT would deadlock because nothing can wake us). When
/// IRQs are masked, falls back to a `spin_loop` hint.
///
/// Note: this has the classic check-halt race when used in a
/// "wait for condition" loop — an IRQ that fires between the
/// caller's condition check and the HLT is serviced *before*
/// HLT executes, so HLT then waits for the *next* IRQ. Use
/// [`idle_halt_then_disable`] from such loops instead; this
/// function is fine for opportunistic idle paths where a missed
/// wake just means we spin again on the next condition check.
#[inline(always)]
pub fn halt_until_irq() {
    if interrupts_enabled() {
        // SAFETY: HLT at CPL=0 with IF=1 wakes on the next IRQ.
        unsafe {
            halt_once();
        }
    } else {
        core::hint::spin_loop();
    }
}

/// Atomic enable-IRQs / halt / disable-IRQs. Mirrors Linux's
/// `default_idle`: `sti; hlt; cli`. The `sti;hlt` pair is special
/// on x86 — IRQs cannot deliver between them, so any IRQ that was
/// pending in the LAPIC IRR when the caller called this still
/// wakes HLT. The trailing `cli` returns with IRQs DISABLED so the
/// caller can re-check the wait condition without a window where
/// an arriving IRQ could be silently consumed before the next
/// halt.
///
/// Canonical wait-for-condition loop:
///
/// ```ignore
/// // SAFETY: caller starts critical section.
/// unsafe { asm!("cli"); }
/// while !condition_met() {
///     // SAFETY: cli above; idle_halt_then_disable returns with cli.
///     unsafe { idle_halt_then_disable(); }
/// }
/// unsafe { asm!("sti"); }
/// ```
///
/// # Safety
/// Caller must currently have IRQs DISABLED (IF=0); otherwise the
/// `sti` here is a no-op and the trailing `cli` mutates surrounding
/// IRQ state. Returns with IRQs DISABLED.
#[inline(always)]
pub unsafe fn idle_halt_then_disable() {
    // SAFETY: caller-asserted IF=0 entering. sti; hlt; cli is
    // atomic on x86 — no IRQ delivers between sti and hlt; HLT
    // then wakes on the IRQ; cli leaves IF=0.
    unsafe {
        core::arch::asm!("sti", "hlt", "cli", options());
    }
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
        loop {
            halt_once();
        }
    }
}

/// 128-bit atomic compare-and-swap via `CMPXCHG16B`.
///
/// # Safety
/// `ptr` must be 16-byte aligned and point to valid, writable memory.
#[inline(always)]
pub unsafe fn cas128(ptr: *mut u128, old: u128, new: u128) -> Result<u128, u128> {
    let old_low = old as u64;
    let old_high = (old >> 64) as u64;
    let new_low = new as u64;
    let new_high = (new >> 64) as u64;

    let res_low: u64;
    let res_high: u64;

    compiler_fence(Ordering::SeqCst);
    // SAFETY: CMPXCHG16B is valid on all NARF-supported x86_64 CPUs
    // (it's a baseline requirement for Stage 3). ptr alignment is the
    // caller's responsibility. RBX is LLVM-reserved, so we stash it
    // manually — and that's why `options(nostack)` is *not* set
    // (the stash touches the stack).
    unsafe {
        asm!(
            "push rbx",
            "mov rbx, {new_low}",
            "lock cmpxchg16b [{ptr}]",
            "pop rbx",
            ptr = in(reg) ptr,
            new_low = in(reg) new_low,
            inout("rax") old_low => res_low,
            inout("rdx") old_high => res_high,
            in("rcx") new_high,
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
/// Used by `tracing/` for runtime probe arming.
///
/// # Safety
/// - `addr` must be 4-byte aligned and point to memory that is both
///   writable (typically via a kernel-writable alias; W^X violation
///   otherwise) and executable.
/// - The old and new bytes must each encode a complete 4-byte boundary:
///   no cross-instruction splits. For NOP-sled arming, the classic NARF
///   sled is 4 bytes of `0x90` + a 4-byte slot that `patch_word` flips.
/// - On single-CPU NARF (Stage 3), the local-serialising `cpuid` at the
///   end is sufficient for the patching CPU to see the new code on its
///   next fetch. SMP requires broadcasting via IPI + targeted
///   `wbinvd`/serializing sequence on every CPU — deferred to Stage 4.
#[inline(always)]
pub unsafe fn patch_word(addr: *mut u32, new: u32) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: aligned 4-byte store is atomic on every x86_64 CPU NARF
    // targets. The caller asserts writable + executable + aligned.
    unsafe {
        core::ptr::write_volatile(addr, new);
    }
    // Serialising instruction: CPUID with EAX=0 is the canonical
    // x86 post-self-modifying-code flush. Spec is clear that an
    // instruction-fetch of modified code without a serialising
    // event is architecturally undefined.
    unsafe {
        // RBX is LLVM-reserved; stash it manually. `nostack` is not set
        // because push/pop touches the stack.
        asm!(
            "push rbx",
            "mov eax, 0",
            "cpuid",
            "pop rbx",
            lateout("eax") _,
            lateout("ecx") _,
            lateout("edx") _,
            options(preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}
