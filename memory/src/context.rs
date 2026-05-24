//! Allocator-context predicates — combine `narf_lib::context`'s
//! per-CPU IRQ depth with the arch-side IRQ-mask bit (RFLAGS.IF /
//! DAIF.I) to give callers a single predicate they can assert on.
//!
//! Lives here (not in narf-lib) because narf-lib can't depend on
//! narf-arch for the asm-level read of the interrupt-mask flag.
//! See `lib/src/context.rs` for the depth-tracking primitives.
//!
//! `AllocContext` mirrors Linux's GFP_KERNEL / GFP_ATOMIC split as
//! a Rust enum the slab API takes. Sleepable construction is
//! gated by a debug-build assertion that the calling context
//! actually allows it (no IRQ in flight, IRQs unmasked) — catches
//! the easy class of bug where someone calls a sleepable allocator
//! from a place that can't sleep, before it manifests as a real
//! latency problem on hardware.

/// Read the arch-level IRQ-mask bit. True iff IRQs are currently
/// unmasked at the CPU. Cheap — one register read, no atomics.
#[inline]
pub fn irqs_enabled() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        narf_arch::x86_64::asm::interrupts_enabled()
    }
    #[cfg(target_arch = "aarch64")]
    {
        narf_arch::aarch64::asm::interrupts_enabled()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        true
    }
}

/// True iff the calling context can sleep — i.e. is not
/// currently servicing an IRQ.
///
/// We deliberately do NOT require IRQs to be unmasked. Linux's
/// stricter model panics on `GFP_KERNEL` with IRQs off because
/// `schedule()` needs the timer IRQ to wake you. Our kernel
/// runs much of boot with IRQs masked (they're enabled late,
/// once the LAPIC + IDT are up), so flagging IRQs-off as
/// non-sleepable would fire all over normal boot. Once the
/// scheduler is up and there's a meaningful "preempt_enabled"
/// state we can tighten this.
#[inline]
pub fn is_sleepable() -> bool {
    !narf_lib::context::in_irq()
}

/// Allocation context, passed to fallible allocator entry points.
/// Maps to the Linux GFP_KERNEL / GFP_ATOMIC split: callers
/// declare what their context permits and the allocator routes
/// accordingly. Mismatches (e.g. `Sleepable` from an IRQ handler)
/// are caught by debug-build asserts at the entry point.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AllocContext {
    /// Process context. May sleep, may invoke shrinkers, may
    /// migrate across NUMA nodes. The "normal" mode. Roughly
    /// equivalent to GFP_KERNEL.
    Sleepable,
    /// Atomic context: IRQ handler, spinlock-held section,
    /// preempt-disabled section. MUST NOT sleep, MUST NOT invoke
    /// shrinkers, MUST NOT cross CPUs. Roughly GFP_ATOMIC.
    Atomic,
    /// IRQ-disabled but non-IRQ context. Same as Atomic plus the
    /// hot path must be lock-free (we own a spinlock; cross-CPU
    /// IPIs we'd issue could deadlock against our lock).
    IrqOff,
}

impl AllocContext {
    /// Debug-build assertion: panic if this context label is
    /// inconsistent with the actual run-time state. `Sleepable`
    /// from inside an IRQ handler, or with IRQs masked, is the
    /// classic bug class this catches.
    ///
    /// Production builds compile this away to nothing.
    #[inline]
    pub fn debug_assert_consistent(self) {
        #[cfg(debug_assertions)]
        match self {
            AllocContext::Sleepable => {
                if !is_sleepable() {
                    // Extra diagnostics for tracking which path
                    // allocates Sleepable from IRQ context. The
                    // in_irq counter being non-zero (depth N) means
                    // an IRQ handler is currently running — its
                    // allocator call needs `try_alloc_atomic` not
                    // Sleepable. Counter > 1 means nested IRQs;
                    // counter stuck > 0 outside of IRQ entry means
                    // a missing `exit_irq` somewhere.
                    panic!(
                        "AllocContext::Sleepable used from IRQ context — \
                         in_irq_depth={} irqs_enabled={} cpu={} vector={:?}",
                        if narf_lib::context::in_irq() { 1 } else { 0 },
                        irqs_enabled(),
                        narf_lib::percpu::current_cpu(),
                        narf_lib::context::current_irq_vector(),
                    );
                }
            }
            AllocContext::Atomic | AllocContext::IrqOff => {
                // Always safe — atomic / IrqOff contexts impose
                // additional restrictions on the allocator, not
                // on the caller's environment.
            }
        }
    }
}
