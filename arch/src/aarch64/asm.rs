//! Privileged-asm wrappers for aarch64. See `arch/` §4 on the
//! `compiler_fence` discipline.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// Mask IRQs via `MSR DAIFSET, #0x2`.
///
/// # Safety
/// Executes a privileged `MSR DAIFSET` — caller must run at EL1.
#[inline(always)]
pub unsafe fn disable_interrupts() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: DAIFSET with I-bit (0x2) masks IRQs at EL1.
    unsafe {
        asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Unmask IRQs via `MSR DAIFCLR, #0x2`.
///
/// # Safety
/// Executes a privileged `MSR DAIFCLR` — caller must run at EL1 and be
/// prepared for IRQ delivery once the I-bit clears.
#[inline(always)]
pub unsafe fn enable_interrupts() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: DAIFCLR with I-bit (0x2) unmasks IRQs.
    unsafe {
        asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// `WFI` — wait for interrupt.
///
/// # Safety
/// Executes `WFI`; caller must ensure a wake source (live IRQ) exists,
/// otherwise the CPU stalls indefinitely.
#[inline(always)]
pub unsafe fn wfi_once() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: WFI at EL1 stalls until the next IRQ or event.
    unsafe {
        asm!("wfi", options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Mask IRQs and spin on `WFI` forever.
#[inline(always)]
pub fn halt_forever() -> ! {
    // SAFETY: masking and halting is always safe; we never return.
    unsafe {
        disable_interrupts();
        loop {
            wfi_once();
        }
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
        // SAFETY: Valid memory or trusted environment
        unsafe {
            wfi_once();
        }
    } else {
        core::hint::spin_loop();
    }
}

/// aarch64 counterpart to x86_64's `sti; hlt; cli`. The aarch64
/// architecture provides this atomicity natively: WFI does not
/// deliver IRQs that arrived before the WFI but does cause WFI to
/// wake on them, so a `msr DAIFClr, #2; wfi; msr DAIFSet, #2`
/// sequence is the obvious analogue. The trailing DAIFSet returns
/// with IRQs disabled so the caller can re-check without a wake
/// being silently consumed.
///
/// # Safety
/// Caller must currently have IRQs masked (DAIF.I == 1). Returns
/// with IRQs masked.
#[inline(always)]
pub unsafe fn idle_halt_then_disable() {
    // SAFETY: caller-asserted DAIF.I=1 entering. The unmask + wfi
    // + remask sequence is atomic with respect to IRQ delivery on
    // aarch64.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!("msr DAIFClr, #0x2", "wfi", "msr DAIFSet, #0x2", options(),);
    }
}

/// 128-bit atomic compare-and-swap via `CASP`.
///
/// # Safety
/// `ptr` must be 16-byte aligned and point to valid, writable memory.
/// This implementation requires ARMv8.1-LSE support.
#[inline(always)]
pub unsafe fn cas128(ptr: *mut u128, old: u128, new: u128) -> Result<u128, u128> {
    let old_low = old as u64;
    let old_high = (old >> 64) as u64;
    let new_low = new as u64;
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
    // SAFETY: Valid memory or trusted environment
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
    unsafe {
        core::ptr::write_volatile(addr, new);
    }
    // SAFETY: `addr` names 4 bytes we just wrote and which are mapped for
    // the duration; the helper only issues cache maintenance by VA.
    unsafe {
        flush_icache_range(addr as u64, 4);
    }
    compiler_fence(Ordering::SeqCst);
}

/// Cache-line size (bytes) for `DC CVAU` / `IC IVAU`, read from `CTR_EL0`.
///
/// `CTR_EL0.DminLine` (bits 19:16) and `IminLine` (bits 3:0) are
/// log2(words), i.e. the line size is `4 << field`. We take the smaller of
/// the two so a single stride is safe for both maintenance ops.
#[inline]
fn cache_line_bytes() -> u64 {
    let ctr: u64;
    // SAFETY: `MRS .., CTR_EL0` is readable at EL1 (and at EL0 when
    // SCTLR_EL1.UCT permits); it has no side effects.
    unsafe {
        asm!("mrs {c}, ctr_el0", c = out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
    let dmin = 4u64 << ((ctr >> 16) & 0xF);
    let imin = 4u64 << (ctr & 0xF);
    dmin.min(imin).max(4)
}

/// `CTR_EL0.IDC` (bit 28): instruction cache is coherent with the data
/// cache, so `DC CVAU` is not required before `IC IVAU`.
const CTR_IDC: u64 = 1 << 28;
/// `CTR_EL0.DIC` (bit 29): instruction cache invalidation is not required
/// for instruction-to-data coherence, so `IC IVAU` may be skipped.
const CTR_DIC: u64 = 1 << 29;

/// Make newly written bytes in `[base, base + len)` visible to instruction
/// fetch on this PE.
///
/// The architecturally required sequence for self-modifying code
/// (Arm ARM DDI0487, B2.4.4 "Concurrent modification and execution") is
/// **`DC CVAU` per line → `DSB ISH` → `IC IVAU` per line → `DSB ISH` →
/// `ISB`**. NARF's `patch_word` previously skipped the `DC CVAU` step
/// entirely, which is only legal when `CTR_EL0.IDC == 1`. It happened to
/// work on QEMU (`-cpu max` reports IDC) and on cores whose caches are
/// PoU-coherent, and would have failed on a core that is not — silently,
/// by executing stale bytes. A bulk JIT publish writes megabytes rather
/// than a single word, so it hits that far harder than a probe patch does;
/// hence the fix lands here rather than being deferred.
///
/// `DC CVAU` is elided when `CTR_EL0.IDC` is set, and `IC IVAU` when
/// `CTR_EL0.DIC` is set, exactly as Linux's `__flush_cache_user_range`
/// does (`arch/arm64/mm/cache.S`).
///
/// `IC IVAU` is broadcast to the inner-shareable domain by the hardware, so
/// no IPI plumbing is needed — an asymmetry with x86_64 worth remembering.
///
/// # Safety
/// `[base, base + len)` must be mapped and readable for the duration.
/// Cache maintenance by VA on an unmapped address takes a translation
/// fault.
pub unsafe fn flush_icache_range(base: u64, len: u64) {
    if len == 0 {
        return;
    }
    compiler_fence(Ordering::SeqCst);

    let ctr: u64;
    // SAFETY: see `cache_line_bytes`.
    unsafe {
        asm!("mrs {c}, ctr_el0", c = out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
    let line = cache_line_bytes();
    let start = base & !(line - 1);
    let end = base + len;

    if ctr & CTR_IDC == 0 {
        let mut p = start;
        while p < end {
            // SAFETY: cache maintenance by VA over a mapped range.
            unsafe {
                asm!("dc cvau, {a}", a = in(reg) p, options(nostack, preserves_flags));
            }
            p += line;
        }
    }
    // The `DSB` is required even when `DC CVAU` was elided: it orders the
    // *stores* that produced the new instructions ahead of the invalidate.
    // SAFETY: `DSB` is always legal at EL1.
    unsafe {
        asm!("dsb ish", options(nostack, preserves_flags));
    }

    if ctr & CTR_DIC == 0 {
        let mut p = start;
        while p < end {
            // SAFETY: cache maintenance by VA over a mapped range.
            unsafe {
                asm!("ic ivau, {a}", a = in(reg) p, options(nostack, preserves_flags));
            }
            p += line;
        }
        // SAFETY: `DSB` is always legal at EL1.
        unsafe {
            asm!("dsb ish", options(nostack, preserves_flags));
        }
    }

    // SAFETY: `ISB` is always legal at EL1.
    unsafe {
        asm!("isb", options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}
